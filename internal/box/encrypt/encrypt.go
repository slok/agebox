package encrypt

import (
	"context"
	"fmt"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret"
	"github.com/slok/agebox/internal/storage"
)

// ServiceConfig is the configuration of Service
type ServiceConfig struct {
	KeyRepo    storage.KeyRepository
	SecretRepo storage.SecretRepository
	TrackRepo  storage.TrackRepository
	Encrypter  secret.Encrypter
	Logger     log.Logger
}

func (c *ServiceConfig) defaults() error {
	if c.KeyRepo == nil {
		return fmt.Errorf("public keys repository is required")
	}

	if c.SecretRepo == nil {
		return fmt.Errorf("secret repository is required")
	}

	if c.TrackRepo == nil {
		return fmt.Errorf("secret track repository is required")
	}

	if c.Encrypter == nil {
		return fmt.Errorf("encrypted is required")
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "box.encrypt.Service"})

	return nil
}

// Service is the application service for the box encrypting logic.
// The service knows  how to encrypt and discover files to encrypt.
type Service struct {
	keyRepo    storage.KeyRepository
	secretRepo storage.SecretRepository
	trackRepo  storage.TrackRepository
	encrypter  secret.Encrypter
	logger     log.Logger
}

// NewService returns a new service.
func NewService(config ServiceConfig) (*Service, error) {
	err := config.defaults()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &Service{
		keyRepo:    config.KeyRepo,
		secretRepo: config.SecretRepo,
		trackRepo:  config.TrackRepo,
		encrypter:  config.Encrypter,
		logger:     config.Logger,
	}, nil
}

// EncryptBoxRequest is the request to encrypt secrets.
type EncryptBoxRequest struct {
	SecretIDs []string
}

// EncryptBox will encrypt secrets..
func (s Service) EncryptBox(ctx context.Context, r EncryptBoxRequest) error {
	if len(r.SecretIDs) == 0 {
		return fmt.Errorf("0 secrets provided")
	}

	// TODO(slok): Validate secretIDs.

	// Load secret tracks.
	reg, err := s.trackRepo.GetSecretRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not get secrets tracking registry: %w", err)
	}

	// Load keys.
	pubKeys, err := s.keyRepo.ListPublicKeys(ctx)
	if err != nil {
		return fmt.Errorf("could not get public keys: %w", err)
	}

	// Encrypt secrets.
	errored := false
	for _, secretID := range r.SecretIDs {
		logger := s.logger.WithValues(log.Kv{"secret-id": secretID})

		err := s.procesSecret(ctx, pubKeys.Items, secretID)
		if err != nil {
			// We will try our best, if error, log and continue with next secrets.
			logger.Errorf("Secret not ecrypted: %s", err)
			errored = true
			continue
		}

		// Secret encrypted, add to the tracked secrets.
		logger.Infof("Secret encrypted")
		reg.EncryptedSecrets[secretID] = struct{}{}
	}

	// Track the correctly encrypted secrets.
	err = s.trackRepo.SaveSecretRegistry(ctx, *reg)
	if err != nil {
		return fmt.Errorf("could not register encrypted keys: %w", err)
	}

	if errored {
		return fmt.Errorf("could not encrypt all the provided secrets")
	}

	return nil
}

func (s Service) procesSecret(ctx context.Context, keys []model.PublicKey, secretID string) error {
	secret, err := s.secretRepo.GetDecryptedSecret(ctx, secretID)
	if err != nil {
		return fmt.Errorf("could not retrieve secret: %w", err)
	}

	secret, err = s.encrypter.Encrypt(ctx, *secret, keys)
	if err != nil {
		return fmt.Errorf("could not encrypt secret: %w", err)
	}

	err = s.secretRepo.SaveEncryptedSecret(ctx, *secret)
	if err != nil {
		return fmt.Errorf("could not stor encrypted secret: %w", err)
	}

	return nil
}
