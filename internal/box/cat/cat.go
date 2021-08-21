package cat

import (
	"context"
	"fmt"
	"io"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
)

// SecretPrinter knows how to print secrets on screen.
type SecretPrinter interface {
	PrintSecret(ctx context.Context, secret *model.Secret) error
}

//go:generate mockery --case underscore --output catmock --outpkg catmock --name SecretPrinter

type ioWriterSecretPrinter struct {
	w io.Writer
}

// NewIOWriterSecretPrinter returns a new secret printer based on an io.Writer.
func NewIOWriterSecretPrinter(w io.Writer) SecretPrinter {
	return ioWriterSecretPrinter{w: w}
}

func (i ioWriterSecretPrinter) PrintSecret(ctx context.Context, secret *model.Secret) error {
	_, err := fmt.Fprint(i.w, string(secret.DecryptedData))
	if err != nil {
		return fmt.Errorf("could not write secret data on writer: %w", err)
	}

	return nil
}

// ServiceConfig is the configuration of Service.
type ServiceConfig struct {
	KeyRepo           storage.KeyRepository
	SecretRepo        storage.SecretRepository
	Encrypter         encrypt.Encrypter
	SecretIDProcessor process.IDProcessor
	SecretPrinter     SecretPrinter
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

	if c.SecretPrinter == nil {
		return fmt.Errorf("secret printer is required")
	}

	if c.SecretIDProcessor == nil {
		c.SecretIDProcessor = process.NoopIDProcessor
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "box.cat.Service"})

	return nil
}

// Service is the application service for the box decrypting cat logic.
// The service knows how to decrypt and print them on screen.
type Service struct {
	keyRepo           storage.KeyRepository
	secretRepo        storage.SecretRepository
	encrypter         encrypt.Encrypter
	secretIDProcessor process.IDProcessor
	secretPrinter     SecretPrinter
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
		secretPrinter:     config.SecretPrinter,
		logger:            config.Logger,
	}, nil
}

// BoxRequest is the request to cat encrypted secrets.
type BoxRequest struct {
	SecretIDs []string
}

// CatBox will decrypt secrets and print them.
func (s Service) CatBox(ctx context.Context, r BoxRequest) error {
	if len(r.SecretIDs) == 0 {
		return fmt.Errorf("0 secrets provided")
	}

	secretIDs := []string{}
	for _, secret := range r.SecretIDs {
		pSecret, err := s.secretIDProcessor.ProcessID(ctx, secret)
		if err != nil {
			return fmt.Errorf("invalid secret %q: %w", secret, err)
		}

		// Ignore.
		if pSecret == "" {
			continue
		}

		secretIDs = append(secretIDs, pSecret)
	}

	// Load key.
	privKeys, err := s.keyRepo.ListPrivateKeys(ctx)
	if err != nil {
		return fmt.Errorf("could not get private key: %w", err)
	}

	// TODO(slok): Make it concurrent.
	for _, secretID := range secretIDs {
		logger := s.logger.WithValues(log.Kv{"secret-id": secretID})

		err := s.procesSecret(ctx, logger, privKeys.Items, secretID)
		if err != nil {
			return fmt.Errorf("could not decrypt all the provided secrets")
		}

		// Secret "cated".
		logger.Infof("Secret decrypted and printed")
	}

	return nil
}

func (s Service) procesSecret(ctx context.Context, logger log.Logger, keys []model.PrivateKey, secretID string) error {
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
			return fmt.Errorf("could not retrieve secret: %w", err)
		}

		secret, err = s.encrypter.Decrypt(ctx, *secret, keys)
		if err != nil {
			return fmt.Errorf("could not decrypt secret: %w", err)
		}
	} else {
		secret, err = s.secretRepo.GetDecryptedSecret(ctx, secretID)
		if err != nil {
			return fmt.Errorf("could not retrieve decrypted secret: %w", err)
		}

		logger.Debugf("Secret already decrypted")
	}

	err = s.secretPrinter.PrintSecret(ctx, secret)
	if err != nil {
		return fmt.Errorf("could not print secret: %w", err)
	}

	return nil
}
