package age

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/slok/agebox/internal/log"
)

func parseSSHPublic() publicKeyParser {
	return func(ctx context.Context, key string) (age.Recipient, error) {
		return agessh.ParseRecipient(key)
	}
}

var (
	// Some users could make this directly `age-keygen -o ./priv.key 2> ./pub.key`
	// This will create a public key in the form of: `Public key: {KEY}`, so we help the user
	// by removing this so we can load keys of this kind directly, anyway, if the key is invalid
	// for any other reason than this, age library will not load an return an error.
	removeAgeDefPhraseRegexp = regexp.MustCompile("(?m)(^Public key:)")
	removeCommentRegexp      = regexp.MustCompile("(?m)(^#.*$)")
)

func parseAgePublic() publicKeyParser {
	return func(ctx context.Context, key string) (age.Recipient, error) {
		key = removeCommentRegexp.ReplaceAllString(key, "")
		key = removeAgeDefPhraseRegexp.ReplaceAllString(key, "")
		key = strings.TrimSpace(key)

		return age.ParseX25519Recipient(key)
	}
}

func parseAgePrivateFunc() privateKeyParser {
	return func(ctx context.Context, key string) (age.Identity, error) {
		key = removeCommentRegexp.ReplaceAllString(key, "")
		key = strings.TrimSpace(key)

		return age.ParseX25519Identity(key)
	}
}

func parseSSHPrivateFunc(passphraseR io.Reader, logger log.Logger) privateKeyParser {
	return func(ctx context.Context, key string) (age.Identity, error) {
		// Get the SSH private key.
		secretData := []byte(key)
		id, err := agessh.ParseIdentity(secretData)
		if err == nil {
			return id, nil
		}

		// If passphrase required, ask for it.
		sshErr, ok := err.(*ssh.PassphraseMissingError)
		if !ok {
			return nil, err
		}

		if sshErr.PublicKey == nil {
			return nil, fmt.Errorf("passphrase required and public key  can't be obtained from private key")
		}

		// Ask for passphrase and get identity.
		i, err := agessh.NewEncryptedSSHIdentity(sshErr.PublicKey, secretData, askPasswordStdin(passphraseR, logger))
		if err != nil {
			return nil, err
		}

		return i, nil
	}
}

func askPasswordStdin(r io.Reader, logger log.Logger) func() ([]byte, error) {
	return func() ([]byte, error) {
		// If not stdin just return the passphrase.
		if r != os.Stdin {
			return io.ReadAll(r)
		}

		// Check if is a valid terminal and try getting it.
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				return nil, fmt.Errorf("standard input is not available or not a terminal, and opening /dev/tty failed: %v", err)
			}
			defer tty.Close()
			fd = int(tty.Fd())
		}

		// Ask for password.
		logger.Warningf("SSH key passphrase required")
		logger.Infof("Enter passphrase for ssh key: ")

		p, err := term.ReadPassword(fd)
		if err != nil {
			return nil, err
		}

		return p, nil
	}
}
