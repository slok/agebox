package reencrypt

import (
	"context"
	"fmt"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
)

// ServiceConfig is the configuration of Service.
type ServiceConfig struct {
	KeyRepo           storage.KeyRepository
	SecretRepo        storage.SecretRepository
	Encrypter         encrypt.Encrypter
	SecretIDProcessor process.IDProcessor
	Logger            log.Logger
}

func (c *ServiceConfig) defaults() error {
	if c.KeyRepo == nil {
		return fmt.Errorf("public keys repository is required")
	}

	if c.SecretRepo == nil {
		return fmt.Errorf("secret repository is required")
	}

	if c.Encrypter == nil {
		return fmt.Errorf("encrypter is required")
	}

	if c.SecretIDProcessor == nil {
		c.SecretIDProcessor = process.NoopIDProcessor
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "box.encrypt.Service"})

	return nil
}

// Service is the application service for the box reencrypting logic.
// The service knows  how to encrypt and discover files to encrypt.
type Service struct {
	keyRepo           storage.KeyRepository
	secretRepo        storage.SecretRepository
	encrypter         encrypt.Encrypter
	secretIDProcessor process.IDProcessor
	logger            log.Logger
}

// NewService returns a new service.
func NewService(config ServiceConfig) (*Service, error) {
	err := config.defaults()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &Service{
		keyRepo:           config.KeyRepo,
		secretRepo:        config.SecretRepo,
		encrypter:         config.Encrypter,
		secretIDProcessor: config.SecretIDProcessor,
		logger:            config.Logger,
	}, nil
}

// ReencryptBoxRequest is the request to encrypt secrets.
type ReencryptBoxRequest struct {
	SecretIDs []string
}

// ReencryptBox will reencrypt secrets.
func (s Service) ReencryptBox(ctx context.Context, r ReencryptBoxRequest) error {
	if len(r.SecretIDs) == 0 {
		return fmt.Errorf("0 secrets provided")
	}

	secretIDs := []string{}
	for _, secret := range r.SecretIDs {
		secret, err := s.secretIDProcessor.ProcessID(ctx, secret)
		if err != nil {
			return fmt.Errorf("invalid secret %q: %w", secret, err)
		}

		// Ignore.
		if secret == "" {
			continue
		}

		secretIDs = append(secretIDs, secret)
	}

	// Load keys.
	privKey, err := s.keyRepo.GetPrivateKey(ctx)
	if err != nil {
		return fmt.Errorf("could not get public keys: %w", err)
	}
	pubKeys, err := s.keyRepo.ListPublicKeys(ctx)
	if err != nil {
		return fmt.Errorf("could not get public keys: %w", err)
	}

	// Reencrypt secrets.
	// TODO(slok): Make it concurrent.
	for _, secretID := range secretIDs {
		logger := s.logger.WithValues(log.Kv{"secret-id": secretID})

		err := s.procesSecret(ctx, logger, privKey, pubKeys.Items, secretID)
		if err != nil {
			return fmt.Errorf("could not reencrypt all the provided secret: %w", err)
		}

		// Secret reencrypted.
		logger.Infof("Secret reencrypted")
	}

	return nil
}

func (s Service) procesSecret(ctx context.Context, logger log.Logger, privaKey model.PrivateKey, pubKeys []model.PublicKey, secretID string) error {
	exists, err := s.secretRepo.ExistsEncryptedSecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("could not check if the encrypted secret exists: %w", err)
	}

	var secret *model.Secret
	// If encrypted secret exists we need to get the encrypted data and decrypt it.
	// If not, we get the decrypted data and don't do anything else.
	if exists {
		secret, err = s.secretRepo.GetEncryptedSecret(ctx, secretID)
		if err != nil {
			return fmt.Errorf("could not retrieve encrypted secret: %w", err)
		}

		secret, err = s.encrypter.Decrypt(ctx, *secret, privaKey)
		if err != nil {
			return fmt.Errorf("could not decrypt secret: %w", err)
		}

		logger.Debugf("Secret decrypted")
	} else {
		secret, err = s.secretRepo.GetDecryptedSecret(ctx, secretID)
		if err != nil {
			return fmt.Errorf("could not retrieve deecrypted secret: %w", err)
		}

		logger.Debugf("Secret already decrypted")
	}

	// Take decrypted data and encrypt again.
	secret, err = s.encrypter.Encrypt(ctx, *secret, pubKeys)
	if err != nil {
		return fmt.Errorf("could not encrypt secret: %w", err)
	}

	err = s.secretRepo.SaveEncryptedSecret(ctx, *secret)
	if err != nil {
		return fmt.Errorf("could not store encrypted secret: %w", err)
	}

	return nil
}
