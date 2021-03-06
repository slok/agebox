package commands

import (
	"context"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"

	boxdecrypt "github.com/slok/agebox/internal/box/decrypt"
	keyage "github.com/slok/agebox/internal/key/age"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/process"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type decryptCommand struct {
	PrivateKeyPath string
	Files          []string
	DecryptAll     bool
}

// NewDecryptCommand returns the decrypt command.
func NewDecryptCommand(app *kingpin.Application) Command {
	c := &decryptCommand{}
	cmd := app.Command("decrypt", "Decrypts any number of tracked files.")
	cmd.Flag("private-key", "Path to private key.").Required().Short('i').StringVar(&c.PrivateKeyPath)
	cmd.Flag("all", "Decrypts all tracked files.").Short('a').BoolVar(&c.DecryptAll)
	cmd.Arg("files", "Files to decrypt.").StringsVar(&c.Files)

	return c
}

func (d decryptCommand) Name() string { return "decrypt" }
func (d decryptCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	// If we try decrypting all files we can't specify files.
	if d.DecryptAll && len(d.Files) > 0 {
		return fmt.Errorf("while decrypting all tracked files can't use specific files as arguments")
	}

	// Create repositories
	keyRepo, err := storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
		PrivateKeyPath: d.PrivateKeyPath,
		KeyFactory:     keyage.Factory,
		Logger:         logger,
	})
	if err != nil {
		return fmt.Errorf("could not create key repository: %w", err)
	}

	secretRepo, err := storagefs.NewSecretRepository(storagefs.SecretRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create secret repository: %w", err)
	}

	// Create secret ID processor.
	secretIDProc := process.NewIDProcessorChain(
		process.NewPathSanitizer(""),
		process.NewIgnoreAlreadyProcessed(map[string]struct{}{}), // This should be after pathSanitizer.
		process.NewDecryptionPathState(true, secretRepo, logger),
	)

	// Get all tracked files.
	if d.DecryptAll {
		trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{Logger: logger})
		if err != nil {
			return fmt.Errorf("could not create track repository: %w", err)
		}

		tracked, err := trackRepo.GetSecretRegistry(ctx)
		if err != nil {
			return fmt.Errorf("could not get tracked files: %w", err)
		}

		for k := range tracked.EncryptedSecrets {
			d.Files = append(d.Files, k)
		}

		logger.Infof("Using %d tracked files", len(d.Files))
	}

	// Create the application service.
	appSvc, err := boxdecrypt.NewService(boxdecrypt.ServiceConfig{
		KeyRepo:           keyRepo,
		SecretRepo:        secretRepo,
		Encrypter:         encryptage.Encrypter,
		SecretIDProcessor: secretIDProc,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("could not create decrypt service: %w", err)
	}

	err = appSvc.DecryptBox(ctx, boxdecrypt.DecryptBoxRequest{
		SecretIDs: d.Files,
	})
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}

	return nil
}
