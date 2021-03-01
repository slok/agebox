package commands

import (
	"context"
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"

	boxinit "github.com/slok/agebox/internal/box/init"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type initCommand struct{}

// NewInitCommand returns the init command.
func NewInitCommand(app *kingpin.Application) Command {
	app.Command("init", "Initializes the repository (box) for encrypting files with agebox.")
	return initCommand{}
}

func (i initCommand) Name() string { return "init" }
func (i initCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	// Create tracker repository.
	trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create track repository: %w", err)
	}

	// Create the application service.
	appSvc, err := boxinit.NewService(boxinit.ServiceConfig{
		TrackRepo: trackRepo,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("could not create init service: %w", err)
	}

	err = appSvc.InitBox(ctx)
	if err != nil {
		return fmt.Errorf("could not init box: %w", err)
	}

	return nil

}
