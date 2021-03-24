package commands

import (
	"os"
	"path/filepath"
)

var defaultSSHDir = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return filepath.Join(home, ".ssh")
}()
