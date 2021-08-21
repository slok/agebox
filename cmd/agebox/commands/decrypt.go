package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"

	boxdecrypt "github.com/slok/agebox/internal/box/decrypt"
	keyage "github.com/slok/agebox/internal/key/age"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/expand"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type decryptCommand struct {
	DeprecatedPrivateKeyPath string
	PrivateKeysPath          string
	Files                    []string
	DecryptAll               bool
	Force                    bool
	DryRun                   bool
	SSHPassphrase            string
	RegexFilter              *regexp.Regexp
}

// NewDecryptCommand returns the decrypt command.
func NewDecryptCommand(app *kingpin.Application) Command {
	c := &decryptCommand{}
	cmd := app.Command("decrypt", "Decrypts any number of tracked files.")
	cmd.Flag("private-key", "DEPRECATED: Use --private-keys.").StringVar(&c.DeprecatedPrivateKeyPath)
	cmd.Flag("private-keys", "Path to private key(s).").Default(defaultSSHDir).Short('i').StringVar(&c.PrivateKeysPath)
	cmd.Flag("passphrase", "SSH private key passphrase, if required it will take this and not ask disabling interactive mode.").StringVar(&c.SSHPassphrase)
	cmd.Flag("all", "Decrypts all tracked files.").Short('a').BoolVar(&c.DecryptAll)
	cmd.Flag("dry-run", "Enables dry run mode, write operations will be ignored.").BoolVar(&c.DryRun)
	cmd.Flag("force", "Forces the decryption even if decrypted file exists.").BoolVar(&c.Force)
	cmd.Flag("filter", "Decrypts only the filenames (without encrypted extension) that match the provided regex.").Short('f').RegexpVar(&c.RegexFilter)
	cmd.Arg("files", "Files to decrypt.").StringsVar(&c.Files)

	return c
}

func (d decryptCommand) Name() string { return "decrypt" }
func (d decryptCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	// Get private key and allow deprecated key flag.
	privateKeysPath := d.PrivateKeysPath
	if d.DeprecatedPrivateKeyPath != "" {
		logger.Warningf("--private-key flag is deprecated, use --private-keys")
		privateKeysPath = d.DeprecatedPrivateKeyPath
	}
	if privateKeysPath == "" {
		return fmt.Errorf("private key is required")
	}

	// If we try decrypting all files we can't specify files.
	if d.DecryptAll && len(d.Files) > 0 {
		return fmt.Errorf("while decrypting all tracked files can't use specific files as arguments")
	}

	var (
		keyRepo    storage.KeyRepository
		secretRepo storage.SecretRepository
	)

	var passphraseR io.Reader = os.Stdin
	if d.SSHPassphrase != "" {
		passphraseR = strings.NewReader(d.SSHPassphrase)
	}

	// Create repositories
	keyRepo, err := storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
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
	if d.DryRun {
		logger.Warningf("Dry run mode enabled")
		keyRepo = storage.NewDryRunKeyRepository(logger, keyRepo)
		secretRepo = storage.NewDryRunSecretRepository(logger, secretRepo)
	}

	// Create secret ID processor.
	secretIDProc := process.NewIDProcessorChain(
		process.NewPathSanitizer(""),
		process.NewIgnoreAlreadyProcessed(map[string]struct{}{}), // This should be after pathSanitizer.
		process.NewIncludeRegexMatch(d.RegexFilter, logger),
		process.NewDecryptionPathState(d.Force, secretRepo, logger),
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
	} else {
		// Expand files in recursive mode.
		expander := expand.NewFSExpander(os.DirFS("."))
		d.Files, err = expander.Expand(ctx, d.Files)
		if err != nil {
			return fmt.Errorf("could not expand files recursively: %w", err)
		}
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

	err = appSvc.DecryptBox(ctx, boxdecrypt.BoxRequest{
		SecretIDs: d.Files,
	})
	if err != nil {
		return fmt.Errorf("could not decrypt: %w", err)
	}

	return nil
}
