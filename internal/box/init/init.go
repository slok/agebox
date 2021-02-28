package init

import (
	"context"
	"fmt"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
)

// TrackRepository is the repository used to track the secret registry.
type TrackRepository interface {
	GetSecretRegistry(ctx context.Context) (*model.SecretRegistry, error)
	SaveSecretRegistry(ctx context.Context, reg model.SecretRegistry) error
}

//go:generate mockery --case underscore --output initmock --outpkg initmock --name TrackRepository

// ServiceConfig is the configuration of Service
type ServiceConfig struct {
	TrackRepo TrackRepository
	Logger    log.Logger
}

func (c *ServiceConfig) defaults() error {
	if c.TrackRepo == nil {
		return fmt.Errorf("track repository is required")
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "box.init.Service"})

	return nil
}

// Service is the application service for the box init logic.
// This service will initialize the repository/box by creating
// a new secret tracking file.
type Service struct {
	trackRepo TrackRepository
	logger    log.Logger
}

// NewService returns a new service.
func NewService(config ServiceConfig) (*Service, error) {
	err := config.defaults()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &Service{
		trackRepo: config.TrackRepo,
		logger:    config.Logger,
	}, nil
}

// InitBox will initialize the box of secrets.
func (s Service) InitBox(ctx context.Context) error {
	// If we can retrieve the secret registry means that we are already initialized.
	// TODO(slok): Use a sentinel error on the track repo.
	_, err := s.trackRepo.GetSecretRegistry(ctx)
	if err == nil {
		return fmt.Errorf("already initialized")
	}

	// Initialize registry without anything.
	err = s.trackRepo.SaveSecretRegistry(ctx, model.SecretRegistry{})
	if err != nil {
		return fmt.Errorf("could not initialize secret registry: %w", err)
	}

	s.logger.Infof("Box initialized")

	return nil
}
