package main

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Setup application commands.
var commands = map[string]Command{
	InitCommand.Name: InitCommand,
}

// Version is the application version.
var Version = "dev"

// Run runs the main application.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// Load command configuration.
	config, err := NewCmdConfig(args[1:], commands)
	if err != nil {
		return fmt.Errorf("invalid command configuration: %w", err)
	}

	// Execute command.
	err = commands[config.Command].Run(ctx, stdin, stdout, stderr, *config)
	if err != nil {
		return fmt.Errorf("%q command failed: %w", config.Command, err)
	}

	return nil
}

func main() {
	ctx := context.Background()
	err := Run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err)
		os.Exit(1)
	}
}
