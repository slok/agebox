package commands

import (
	"context"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"

	boxreencrypt "github.com/slok/agebox/internal/box/reencrypt"
	keyage "github.com/slok/agebox/internal/key/age"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/process"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type reencryptCommand struct {
	PubKeysPath    string
	PrivateKeyPath string
}

// NewReencryptCommand returns the reencrypt command.
func NewReencryptCommand(app *kingpin.Application) Command {
	c := &reencryptCommand{}
	cmd := app.Command("reencrypt", "Reencrypts the tracked files.")
	cmd.Alias("recrypt")
	cmd.Flag("public-keys", "Path to public keys.").Default("keys").Short('p').StringVar(&c.PubKeysPath)
	cmd.Flag("private-key", "Path to private key.").Required().Short('i').StringVar(&c.PrivateKeyPath)

	return c
}

func (r reencryptCommand) Name() string { return "reencrypt" }
func (r reencryptCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create track repository: %w", err)
	}

	keyRepo, err := storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
		PublicKeysPath: r.PubKeysPath,
		PrivateKeyPath: r.PrivateKeyPath,
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
	)

	// Get all tracked files.
	tracked, err := trackRepo.GetSecretRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not get tracked files: %w", err)
	}

	files := []string{}
	for k := range tracked.EncryptedSecrets {
		files = append(files, k)
	}

	logger.Infof("Using %d tracked files", len(files))

	// Create the application service.
	appSvc, err := boxreencrypt.NewService(boxreencrypt.ServiceConfig{
		KeyRepo:           keyRepo,
		SecretRepo:        secretRepo,
		Encrypter:         encryptage.Encrypter,
		SecretIDProcessor: secretIDProc,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("could not create reencrypt service: %w", err)
	}

	err = appSvc.ReencryptBox(ctx, boxreencrypt.ReencryptBoxRequest{
		SecretIDs: files,
	})
	if err != nil {
		return fmt.Errorf("could not encrypt: %w", err)
	}

	return nil
}
