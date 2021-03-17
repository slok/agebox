package validate

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
		return fmt.Errorf("keys repository is required")
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
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "box.validate.Service"})

	return nil
}

// Service is the application service for the box validation logic.
// The service knows how to check and decrypt.
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

// ValidateBoxRequest is the request to validate secrets.
type ValidateBoxRequest struct {
	SecretIDs []string
	Decrypt   bool
}

// ValidateBox will validate secrets.
func (s Service) ValidateBox(ctx context.Context, r ValidateBoxRequest) error {
	if len(r.SecretIDs) == 0 {
		return fmt.Errorf("0 secrets provided")
	}

	secretIDs := []string{}
	errored := false
	for _, secretID := range r.SecretIDs {
		logger := s.logger.WithValues(log.Kv{"secret-id": secretID})

		pSecret, err := s.secretIDProcessor.ProcessID(ctx, secretID)
		if err != nil {
			// We will try our best, if error, log and continue with next secrets.
			logger.Errorf("Invalid secret: %s", err)
			errored = true
			continue
		}

		// Ignore.
		if pSecret == "" {
			continue
		}

		secretIDs = append(secretIDs, pSecret)
	}

	if errored {
		return fmt.Errorf("validation process failed")
	}

	// If no decryption required just end here.
	if !r.Decrypt {
		return nil
	}

	// Load key.
	privKey, err := s.keyRepo.GetPrivateKey(ctx)
	if err != nil {
		return fmt.Errorf("could not get private key: %w", err)
	}

	// Validate secrets.
	// TODO(slok): Make it concurrent.
	errored = false
	for _, secretID := range secretIDs {
		logger := s.logger.WithValues(log.Kv{"secret-id": secretID})

		err := s.procesSecret(ctx, privKey, secretID)
		if err != nil {
			// We will try our best, if error, log and continue with next secrets.
			logger.Errorf("Invalid secret: %s", err)
			errored = true
			continue
		}
	}

	if errored {
		return fmt.Errorf("validation process failed")
	}

	return nil
}

func (s Service) procesSecret(ctx context.Context, key model.PrivateKey, secretID string) error {
	secret, err := s.secretRepo.GetEncryptedSecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("could not retrieve secret: %w", err)
	}

	_, err = s.encrypter.Decrypt(ctx, *secret, key)
	if err != nil {
		return fmt.Errorf("could not decrypt secret: %w", err)
	}

	return nil
}
