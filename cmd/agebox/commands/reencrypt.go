package commands

import (
	"context"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"

	boxreencrypt "github.com/slok/agebox/internal/box/reencrypt"
	keyage "github.com/slok/agebox/internal/key/age"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type reencryptCommand struct {
	PubKeysPath              string
	DeprecatedPrivateKeyPath string
	PrivateKeysPath          string
	SSHPassphrase            string
	SSHPassphraseEnv         string
	DryRun                   bool
}

// NewReencryptCommand returns the reencrypt command.
func NewReencryptCommand(app *kingpin.Application) Command {
	c := &reencryptCommand{}
	cmd := app.Command("reencrypt", "Reencrypts the tracked files.")
	cmd.Alias("recrypt")
	cmd.Alias("update")
	cmd.Flag("public-keys", "Path to public keys.").Default("keys").Short('p').StringVar(&c.PubKeysPath)
	cmd.Flag("private-key", "DEPRECATED: Use --private-keys.").StringVar(&c.DeprecatedPrivateKeyPath)
	cmd.Flag("private-keys", "Path to private key(s).").Default(defaultSSHDir).Short('i').StringVar(&c.PrivateKeysPath)
	cmd.Flag("passphrase", "SSH private key passphrase, if required it will take this and not ask disabling interactive mode (if `-` is used it will read from stdin).").StringVar(&c.SSHPassphrase)
	cmd.Flag("passphrase-env", "Same as `passphrase` except it will get the passphrase from the specified env var").StringVar(&c.SSHPassphraseEnv)
	cmd.Flag("dry-run", "Enables dry run mode, write operations will be ignored.").BoolVar(&c.DryRun)

	return c
}

func (r reencryptCommand) Name() string { return "reencrypt" }
func (r reencryptCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	// Get private key and allow deprecated key flag.
	privateKeysPath := r.PrivateKeysPath
	if r.DeprecatedPrivateKeyPath != "" {
		logger.Warningf("--private-key flag is deprecated, use --private-keys")
		privateKeysPath = r.DeprecatedPrivateKeyPath
	}
	if privateKeysPath == "" {
		return fmt.Errorf("private key is required")
	}

	var (
		trackRepo  storage.TrackRepository
		keyRepo    storage.KeyRepository
		secretRepo storage.SecretRepository
	)

	trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create track repository: %w", err)
	}

	// Handle passphrase different inputs.
	passphraseR, err := getPassphraseReader(r.SSHPassphrase, r.SSHPassphraseEnv)
	if err != nil {
		return err
	}

	keyRepo, err = storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
		PublicKeysPath:  r.PubKeysPath,
		PrivateKeysPath: privateKeysPath,
		KeyFactory:      keyage.NewFactory(passphraseR, logger),
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("could not create key repository: %w", err)
	}

	secretRepo, err = storagefs.NewSecretRepository(storagefs.SecretRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create secret repository: %w", err)
	}

	// If we are in dry-run set the correct repositories.
	if r.DryRun {
		logger.Warningf("Dry run mode enabled")
		trackRepo = storage.NewDryRunTrackRepository(logger, trackRepo)
		keyRepo = storage.NewDryRunKeyRepository(logger, keyRepo)
		secretRepo = storage.NewDryRunSecretRepository(logger, secretRepo)
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

	err = appSvc.ReencryptBox(ctx, boxreencrypt.BoxRequest{
		SecretIDs: files,
	})
	if err != nil {
		return fmt.Errorf("could not encrypt: %w", err)
	}

	return nil
}
