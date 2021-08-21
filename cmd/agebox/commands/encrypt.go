package commands

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/alecthomas/kingpin.v2"

	boxencrypt "github.com/slok/agebox/internal/box/encrypt"
	keyage "github.com/slok/agebox/internal/key/age"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/expand"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type encryptCommand struct {
	PubKeysPath string
	Files       []string
	EncryptAll  bool
	DryRun      bool
	RegexFilter *regexp.Regexp
}

// NewEncryptCommand returns the encrypt command.
func NewEncryptCommand(app *kingpin.Application) Command {
	c := &encryptCommand{}
	cmd := app.Command("encrypt", "Encrypts and tracks any number of files.")
	cmd.Flag("public-keys", "Path to public keys.").Default("keys").Short('p').StringVar(&c.PubKeysPath)
	cmd.Flag("all", "Encrypts all tracked files.").Short('a').BoolVar(&c.EncryptAll)
	cmd.Flag("dry-run", "Enables dry run mode, write operations will be ignored.").BoolVar(&c.DryRun)
	cmd.Flag("filter", "Encrypts only the filenames (without encrypted extension) that match the provided regex").Short('f').RegexpVar(&c.RegexFilter)
	cmd.Arg("files", "Files to encrypt.").StringsVar(&c.Files)

	return c
}

func (e encryptCommand) Name() string { return "encrypt" }
func (e encryptCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	// If we try encrypting all files we can't specify files.
	if e.EncryptAll && len(e.Files) > 0 {
		return fmt.Errorf("while encrypting all tracked files can't use specific files as arguments")
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

	keyRepo, err = storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
		PublicKeysPath: e.PubKeysPath,
		KeyFactory:     keyage.NewFactory(config.Stdin, logger),
		Logger:         logger,
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
	if e.DryRun {
		logger.Warningf("Dry run mode enabled")
		trackRepo = storage.NewDryRunTrackRepository(logger, trackRepo)
		keyRepo = storage.NewDryRunKeyRepository(logger, keyRepo)
		secretRepo = storage.NewDryRunSecretRepository(logger, secretRepo)
	}

	// Create secret ID processor.
	secretIDProc := process.NewIDProcessorChain(
		process.NewPathSanitizer(""),
		process.NewIgnoreAlreadyProcessed(map[string]struct{}{}), // This should be after pathSanitizer.
		process.NewIncludeRegexMatch(e.RegexFilter, logger),
		process.NewEncryptionPathState(secretRepo, logger),
	)

	// Get all tracked files.
	if e.EncryptAll {
		tracked, err := trackRepo.GetSecretRegistry(ctx)
		if err != nil {
			return fmt.Errorf("could not get tracked files: %w", err)
		}

		for k := range tracked.EncryptedSecrets {
			e.Files = append(e.Files, k)
		}

		logger.Infof("Using %d tracked files", len(e.Files))
	} else {
		// Expand files in recursive mode.
		expander := expand.NewFSExpander(os.DirFS("."))
		e.Files, err = expander.Expand(ctx, e.Files)
		if err != nil {
			return fmt.Errorf("could not expand files recursively: %w", err)
		}
	}

	// Create the application service.
	appSvc, err := boxencrypt.NewService(boxencrypt.ServiceConfig{
		TrackRepo:         trackRepo,
		KeyRepo:           keyRepo,
		SecretRepo:        secretRepo,
		Encrypter:         encryptage.Encrypter,
		SecretIDProcessor: secretIDProc,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("could not create encrypt service: %w", err)
	}

	err = appSvc.EncryptBox(ctx, boxencrypt.BoxRequest{
		SecretIDs: e.Files,
	})
	if err != nil {
		return fmt.Errorf("could not encrypt: %w", err)
	}

	return nil
}
