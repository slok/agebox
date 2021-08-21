package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"

	boxvalidate "github.com/slok/agebox/internal/box/validate"
	keyage "github.com/slok/agebox/internal/key/age"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/process"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type validateCommand struct {
	DeprecatedPrivateKeyPath string
	PrivateKeysPath          string
	SSHPassphrase            string
	NoDecrypt                bool
}

// NewValidateCommand returns the validate command.
func NewValidateCommand(app *kingpin.Application) Command {
	c := &validateCommand{}
	cmd := app.Command("validate", "Validates the files are in correct state (e.g encrypted and not decrypted).")
	cmd.Alias("check")
	cmd.Flag("private-key", "DEPRECATED: Use --private-keys.").StringVar(&c.DeprecatedPrivateKeyPath)
	cmd.Flag("private-keys", "Path to private key(s).").Default(defaultSSHDir).Short('i').StringVar(&c.PrivateKeysPath)
	cmd.Flag("passphrase", "SSH private key passphrase, if required it will take this and not ask disabling interactive mode.").StringVar(&c.SSHPassphrase)
	cmd.Flag("no-decrypt", "Doesn't decrypt the tracked files.").BoolVar(&c.NoDecrypt)

	return c
}

func (v validateCommand) Name() string { return "validate" }
func (v validateCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	// If decrypting is required get private key and allow deprecated key flag.
	privateKeysPath := v.PrivateKeysPath
	if !v.NoDecrypt {
		if v.DeprecatedPrivateKeyPath != "" {
			logger.Warningf("--private-key flag is deprecated, use --private-keys")
			privateKeysPath = v.DeprecatedPrivateKeyPath
		}
		if privateKeysPath == "" {
			return fmt.Errorf("private key is required")
		}
	}

	var passphraseR io.Reader = os.Stdin
	if v.SSHPassphrase != "" {
		passphraseR = strings.NewReader(v.SSHPassphrase)
	}

	// Create repositories.
	keyRepo, err := storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
		PrivateKeysPath: privateKeysPath,
		KeyFactory:      keyage.NewFactory(passphraseR, logger),
		Logger:          logger,
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
		process.NewEncryptedValidationPathState(secretRepo),
	)

	// Get all tracked files.
	trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{Logger: logger})
	if err != nil {
		return fmt.Errorf("could not create track repository: %w", err)
	}

	tracked, err := trackRepo.GetSecretRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not get tracked files: %w", err)
	}

	files := make([]string, 0, len(tracked.EncryptedSecrets))
	for k := range tracked.EncryptedSecrets {
		files = append(files, k)
	}

	logger.Infof("Using %d tracked files", len(files))

	// Create the application service.
	appSvc, err := boxvalidate.NewService(boxvalidate.ServiceConfig{
		KeyRepo:           keyRepo,
		SecretRepo:        secretRepo,
		Encrypter:         encryptage.Encrypter,
		SecretIDProcessor: secretIDProc,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("could not create validation service: %w", err)
	}

	err = appSvc.ValidateBox(ctx, boxvalidate.BoxRequest{
		Decrypt:   !v.NoDecrypt,
		SecretIDs: files,
	})
	if err != nil {
		return fmt.Errorf("not valid: %w", err)
	}

	logger.Infof("Validation successful")

	return nil
}
