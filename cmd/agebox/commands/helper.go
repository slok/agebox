package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var defaultSSHDir = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return filepath.Join(home, ".ssh")
}()

// getPassphraseReader will get the passphrase reader from the different supported formats.
func getPassphraseReader(passphrase, passphraseEnv string) (io.Reader, error) {
	var passphraseR io.Reader
	switch {
	case passphrase != "" && passphraseEnv != "":
		return nil, fmt.Errorf("passphrase and passphrase env can't be used at the same time")
	case passphrase == "" && passphraseEnv == "":
		passphraseR = os.Stdin
	case passphraseEnv != "":
		pp, ok := os.LookupEnv(passphraseEnv)
		if !ok {
			return nil, fmt.Errorf("env var %q is missing", passphraseEnv)
		}
		passphraseR = strings.NewReader(pp)
	case passphrase == "-":
		pp, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("could not read from stdin")
		}
		pp = bytes.TrimSpace(pp)
		passphraseR = bytes.NewReader(pp)
	default:
		passphraseR = strings.NewReader(passphrase)
	}

	return passphraseR, nil
}
