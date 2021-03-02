package commands

import (
	"context"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"

	boxencrypt "github.com/slok/agebox/internal/box/encrypt"
	keyage "github.com/slok/agebox/internal/key/age"
	secretage "github.com/slok/agebox/internal/secret/age"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type encryptCommand struct {
	PubKeysPath string
	Files       []string
}

// NewEncryptCommand returns the encrypt command.
func NewEncryptCommand(app *kingpin.Application) Command {
	c := &encryptCommand{}
	cmd := app.Command("encrypt", "Encrypts and tracks any number of files.")
	cmd.Flag("public-keys", "Path to public keys.").Default("keys").Short('p').StringVar(&c.PubKeysPath)
	cmd.Arg("files", "Files to encrypt.").StringsVar(&c.Files)

	return c
}

func (e encryptCommand) Name() string { return "encrypt" }
func (e encryptCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create track repository: %w", err)
	}

	keyRepo, err := storagefs.NewKeyRepository(storagefs.KeyRepositoryConfig{
		PublicKeysPath: e.PubKeysPath,
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

	// Create the application service.
	appSvc, err := boxencrypt.NewService(boxencrypt.ServiceConfig{
		TrackRepo:  trackRepo,
		KeyRepo:    keyRepo,
		SecretRepo: secretRepo,
		Encrypter:  secretage.Encrypter,
		Logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("could not create encrypt service: %w", err)
	}

	err = appSvc.EncryptBox(ctx, boxencrypt.EncryptBoxRequest{
		SecretIDs: e.Files,
	})
	if err != nil {
		return fmt.Errorf("could not encrypt: %w", err)
	}

	return nil
}
