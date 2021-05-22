package age

import (
	"context"
	"fmt"
	"io"

	"filippo.io/age"

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

type publicKeyParser func(ctx context.Context, key string) (age.Recipient, error)
type privateKeyParser func(ctx context.Context, key string) (age.Identity, error)

type factory struct {
	// These are the key parsers used to load keys, they will work in
	// brute force mode being used as a chain, if one fails we continue
	// until one is correct.
	//
	// TODO(slok): We could optimize this as age does, checking
	//			   the keys headers and selecting the correct one.
	publicKeyParsers  []publicKeyParser
	privateKeyParsers []privateKeyParser
}

// Factory is the key.Factory implementation for age supported keys.
// It supports:
// - RSA
// - Ed25519
// - X25519
func NewFactory(passphraseReader io.Reader, logger log.Logger) key.Factory {
	logger = logger.WithValues(log.Kv{"svc": "key.age.Factory"})

	return factory{
		publicKeyParsers: []publicKeyParser{
			parseSSHPublic(),
			parseAgePublic(),
		},
		privateKeyParsers: []privateKeyParser{
			parseSSHPrivateFunc(passphraseReader, logger),
			parseAgePrivateFunc(),
		},
	}
}

var _ key.Factory = factory{}

func (f factory) GetPublicKey(ctx context.Context, data []byte) (model.PublicKey, error) {
	sdata := string(data)
	for _, f := range f.publicKeyParsers {
		recipient, err := f(ctx, sdata)
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
		identity, err := f(ctx, sdata)
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
