package commands

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/alecthomas/kingpin.v2"

	boxuntrack "github.com/slok/agebox/internal/box/untrack"
	"github.com/slok/agebox/internal/secret/expand"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type untrackCommand struct {
	Files       []string
	Delete      bool
	DryRun      bool
	RegexFilter *regexp.Regexp
}

// NewUntrackCommand returns the untrack command.
func NewUntrackCommand(app *kingpin.Application) Command {
	c := &untrackCommand{}
	cmd := app.Command("untrack", "Untracks any number of tracked files.")
	cmd.Alias("rm")
	cmd.Flag("dry-run", "Enables dry run mode, write operations will be ignored").BoolVar(&c.DryRun)
	cmd.Flag("delete", "Deletes the untracked files, encrypted or decrypted").BoolVar(&c.Delete)
	cmd.Flag("filter", "Untracks only the filenames (without encrypted extension) that match the provided regex").Short('f').RegexpVar(&c.RegexFilter)
	cmd.Arg("files", "Files to decrypt.").StringsVar(&c.Files)

	return c
}

func (u untrackCommand) Name() string { return "untrack" }
func (u untrackCommand) Run(ctx context.Context, config RootConfig) error {
	logger := config.Logger

	var (
		trackRepo  storage.TrackRepository
		secretRepo storage.SecretRepository
	)

	trackRepo, err := storagefs.NewTrackRepository(storagefs.TrackRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create track repository: %w", err)
	}

	secretRepo, err = storagefs.NewSecretRepository(storagefs.SecretRepositoryConfig{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("could not create secret repository: %w", err)
	}

	// If we are in dry-run set the correct repositories.
	if u.DryRun {
		logger.Warningf("Dry run mode enabled")
		trackRepo = storage.NewDryRunTrackRepository(logger, trackRepo)
		secretRepo = storage.NewDryRunSecretRepository(logger, secretRepo)
	}

	tracked, err := trackRepo.GetSecretRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not get tracked files: %w", err)
	}

	// Create secret ID processor.
	secretIDProc := process.NewIDProcessorChain(
		process.NewPathSanitizer(""),
		process.NewIgnoreAlreadyProcessed(map[string]struct{}{}), // This should be after pathSanitizer.
		process.NewIncludeRegexMatch(u.RegexFilter, logger),
		process.NewTrackedState(tracked.EncryptedSecrets, true, logger),
	)

	// Expand files in recursive mode.
	expander := expand.NewFSExpander(os.DirFS("."))
	u.Files, err = expander.Expand(ctx, u.Files)
	if err != nil {
		return fmt.Errorf("could not expand files recursively: %w", err)
	}

	// Create the application service.
	appSvc, err := boxuntrack.NewService(boxuntrack.ServiceConfig{
		SecretRepo:        secretRepo,
		TrackRepo:         trackRepo,
		SecretIDProcessor: secretIDProc,
		Logger:            logger,
	})
	if err != nil {
		return fmt.Errorf("could not create untrack service: %w", err)
	}

	err = appSvc.UntrackBox(ctx, boxuntrack.UntrackBoxRequest{
		SecretIDs:       u.Files,
		DeleteUntracked: u.Delete,
	})
	if err != nil {
		return fmt.Errorf("could not untrack: %w", err)
	}

	return nil
}
