package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"

	boxcat "github.com/slok/agebox/internal/box/cat"
	keyage "github.com/slok/agebox/internal/key/age"
	"github.com/slok/agebox/internal/log"
	encryptage "github.com/slok/agebox/internal/secret/encrypt/age"
	"github.com/slok/agebox/internal/secret/process"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type catCommand struct {
	DeprecatedPrivateKeyPath string
	PrivateKeysPath          string
	SSHPassphrase            string
	Files                    []string
}

// NewCatCommand returns the cat command.
func NewCatCommand(app *kingpin.Application) Command {
	c := &catCommand{}
	cmd := app.Command("cat", "Decrypts any number of tracked files and prints them to stdout.")
	cmd.Flag("private-key", "DEPRECATED: Use --private-keys.").StringVar(&c.DeprecatedPrivateKeyPath)
	cmd.Flag("private-keys", "Path to private key(s).").Default(defaultSSHDir).Short('i').StringVar(&c.PrivateKeysPath)
	cmd.Flag("passphrase", "SSH private key passphrase, if required it will take this and not ask disabling interactive mode.").StringVar(&c.SSHPassphrase)
	cmd.Arg("files", "Files to decrypt.").StringsVar(&c.Files)

	return c
}

func (c catCommand) Name() string { return "cat" }
func (c catCommand) Run(ctx context.Context, config RootConfig) error {
	logger := allDebugLogger{Logger: config.Logger}

	// Get private key and allow deprecated key flag.
	privateKeysPath := c.PrivateKeysPath
	if c.DeprecatedPrivateKeyPath != "" {
		logger.Warningf("--private-key flag is deprecated, use --private-keys")
		privateKeysPath = c.DeprecatedPrivateKeyPath
	}
	if privateKeysPath == "" {
		return fmt.Errorf("private key is required")
	}

	var passphraseR io.Reader = os.Stdin
	if c.SSHPassphrase != "" {
		passphraseR = strings.NewReader(c.SSHPassphrase)
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
	)

	// Create the application service.
	appSvc, err := boxcat.NewService(boxcat.ServiceConfig{
		KeyRepo:           keyRepo,
		SecretRepo:        secretRepo,
		Encrypter:         encryptage.Encrypter,
		SecretIDProcessor: secretIDProc,
		SecretPrinter:     boxcat.NewIOWriterSecretPrinter(config.Stdout),
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("could not create cat service: %w", err)
	}

	err = appSvc.CatBox(ctx, boxcat.CatBoxRequest{
		SecretIDs: c.Files,
	})
	if err != nil {
		return fmt.Errorf("could not cat: %w", err)
	}

	return nil
}

// allDebugLogger is a special logger that wraps a Logger and instead
// of info and Warning, it prints in debug mode.
// This way we don't lose information when hidding while using cat.
type allDebugLogger struct {
	log.Logger
}

func (a allDebugLogger) WithValues(kv log.Kv) log.Logger {
	return allDebugLogger{Logger: a.Logger.WithValues(kv)}
}

func (a allDebugLogger) Infof(format string, args ...interface{}) {
	a.Logger.Debugf(format, args...)
}

func (a allDebugLogger) Warningf(format string, args ...interface{}) {
	a.Logger.Debugf(format, args...)
}
