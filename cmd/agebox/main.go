package main

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Version is the application version.
var Version = "dev"

// Run runs the main application.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fmt.Println(Version)
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
