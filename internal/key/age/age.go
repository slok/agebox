package age

import (
	"context"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/slok/agebox/internal/key"
	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
)

// PublicKey is a public key based on age library.
type PublicKey struct {
	data      []byte
	recipient age.Recipient
}

// Data satisfies Key interface.
func (p PublicKey) Data() []byte { return p.data }

// IsPublic satisifies PublicKey interface.
func (PublicKey) IsPublic() {}

// AgeRecipient returns age Recipient.
func (p PublicKey) AgeRecipient() age.Recipient { return p.recipient }

var _ model.PublicKey = &PublicKey{}

// PrivateKey is a private key based on age library.
type PrivateKey struct {
	data     []byte
	identity age.Identity
}

// Data satisfies Key interface.
func (p PrivateKey) Data() []byte { return p.data }

// IsPrivate satisifies PrivateKey interface.
func (PrivateKey) IsPrivate() {}

// AgeIdentity returns age Identity.
func (p PrivateKey) AgeIdentity() age.Identity { return p.identity }

var _ model.PrivateKey = &PrivateKey{}

type factory struct {
	// These are the key parsers used to load keys, they will work in
	// brute force mode being used as a chain, if one fails we continue
	// until one is correct.
	//
	// TODO(slok): We could optimize this as age does, checking
	//			   the keys headers and selecting the correct one.
	publicKeyParsers  []func(string) (age.Recipient, error)
	privateKeyParsers []func(string) (age.Identity, error)
}

// Factory is the key.Factory implementation for age supported keys.
// It supports:
// - RSA
// - Ed25519
// - X25519
func NewFactory(passphraseReader io.Reader, logger log.Logger) key.Factory {
	logger = logger.WithValues(log.Kv{"svc": "key.age.Factory"})

	return factory{
		publicKeyParsers: []func(string) (age.Recipient, error){
			agessh.ParseRecipient,
			func(d string) (age.Recipient, error) { return age.ParseX25519Recipient(d) },
		},
		privateKeyParsers: []func(string) (age.Identity, error){
			parseSSHIdentityFunc(passphraseReader, logger),
			func(d string) (age.Identity, error) { return age.ParseX25519Identity(d) },
		},
	}
}

var _ key.Factory = factory{}

func (f factory) GetPublicKey(ctx context.Context, data []byte) (model.PublicKey, error) {
	sdata := string(data)
	for _, f := range f.publicKeyParsers {
		recipient, err := f(sdata)
		// If no error, we have our public key.
		if err == nil {
			return PublicKey{
				data:      data,
				recipient: recipient,
			}, nil
		}
	}

	return nil, fmt.Errorf("invalid public key")
}

func (f factory) GetPrivateKey(ctx context.Context, data []byte) (model.PrivateKey, error) {
	sdata := string(data)
	for _, f := range f.privateKeyParsers {
		identity, err := f(sdata)
		// If no error, we have our private key.
		if err == nil {
			return PrivateKey{
				data:     data,
				identity: identity,
			}, nil
		}
	}

	return nil, fmt.Errorf("invalid private key")
}

func parseSSHIdentityFunc(passphraseR io.Reader, logger log.Logger) func(string) (age.Identity, error) {
	return func(d string) (age.Identity, error) {
		// Get the SSH private key.
		secretData := []byte(d)
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
