package untrack

import (
	"context"
	"fmt"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
)

// ServiceConfig is the configuration of Service.
type ServiceConfig struct {
	SecretRepo        storage.SecretRepository
	TrackRepo         storage.TrackRepository
	SecretIDProcessor process.IDProcessor
	Logger            log.Logger
}

func (c *ServiceConfig) defaults() error {
	if c.SecretRepo == nil {
		return fmt.Errorf("secret repository is required")
	}

	if c.TrackRepo == nil {
		return fmt.Errorf("secret track repository is required")
	}

	if c.SecretIDProcessor == nil {
		c.SecretIDProcessor = process.NoopIDProcessor
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "box.untrack.Service"})

	return nil
}

// Service is the application service for the box untracking logic.
// The service knows how to untrack.
type Service struct {
	secretRepo        storage.SecretRepository
	trackRepo         storage.TrackRepository
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
		secretRepo:        config.SecretRepo,
		trackRepo:         config.TrackRepo,
		secretIDProcessor: config.SecretIDProcessor,
		logger:            config.Logger,
	}, nil
}

// BoxRequest is the request to untrack secrets.
type BoxRequest struct {
	SecretIDs       []string
	DeleteUntracked bool
}

// UntrackBox will untrack secrets.
func (s Service) UntrackBox(ctx context.Context, r BoxRequest) error {
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

	// Load secret tracks.
	reg, err := s.trackRepo.GetSecretRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not get secrets tracking registry: %w", err)
	}

	// Untrack secrets.
	// TODO(slok): Make it concurrent.
	errored := false
	for _, secretID := range secretIDs {
		logger := s.logger.WithValues(log.Kv{"secret-id": secretID})

		err := s.processSecret(ctx, r.DeleteUntracked, secretID)
		if err != nil {
			// We will try our best, if error, log and continue with next secrets.
			logger.Errorf("Secret not untracked: %s", err)
			errored = true
			continue
		}

		// Secret untracked, remove form tracked secrets.
		logger.Infof("Secret untracked")
		delete(reg.EncryptedSecrets, secretID)
	}

	// Track the correctly untracked secrets.
	err = s.trackRepo.SaveSecretRegistry(ctx, *reg)
	if err != nil {
		return fmt.Errorf("could not register untracked keys: %w", err)
	}

	if errored {
		return fmt.Errorf("could not untrack all the provided secrets")
	}

	return nil
}

func (s Service) processSecret(ctx context.Context, deleteUntracked bool, secretID string) error {
	if !deleteUntracked {
		// Just ignore as a processed, upper layer will remove from the tracking.
		return nil
	}

	// Delete files.
	err := s.secretRepo.DeleteDecryptedSecret(ctx, secretID)
	if err != nil {
		return err
	}

	err = s.secretRepo.DeleteEncryptedSecret(ctx, secretID)
	if err != nil {
		return err
	}

	return nil
}
