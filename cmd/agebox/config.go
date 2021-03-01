package main

import (
	"context"
	"io"

	"gopkg.in/alecthomas/kingpin.v2"
)

// Command represents an application command.
type Command struct {
	Name     string
	Register func(app *kingpin.Application)
	Run      func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, config CmdConfig) error
}

// CmdConfig represents the configuration of the command.
type CmdConfig struct {
	Command string
}

// NewCmdConfig returns a new command configuration.
func NewCmdConfig(args []string, commands map[string]Command) (*CmdConfig, error) {
	c := &CmdConfig{}
	app := kingpin.New("agebox", "Age based repo file encrypt helper.")
	app.Version(Version)
	app.DefaultEnvars()

	// Register command config.
	for _, cmd := range commands {
		cmd.Register(app)
	}

	cmdName, err := app.Parse(args)
	if err != nil {
		return nil, err
	}
	c.Command = cmdName

	return c, nil
}
