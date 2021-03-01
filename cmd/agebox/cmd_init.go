package main

import (
	"context"
	"fmt"
	"io"

	"gopkg.in/alecthomas/kingpin.v2"

	boxinit "github.com/slok/agebox/internal/box/init"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

// InitCommand initializes a repository/box of secrets.
var InitCommand = Command{
	Name: "init",
	Register: func(app *kingpin.Application) {
		app.Command("init", "Initializes the repository (box) for encrypting files with agebox.")
	},
	Run: func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, config CmdConfig) error {
		logger := getLogger(config, stderr)

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
	},
}
