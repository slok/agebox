package age

import (
	"context"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"github.com/slok/agebox/internal/key"
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

// These are the key parsers used to load keys, they will work in
// brute force mode being used as a chain, if one fails we continue
// until one is correct.
//
// TODO(slok): We could optimize this as age does, checking
//			   the keys headers and selecting the correct one.
var (
	publicKeyParsers = []func(string) (age.Recipient, error){
		agessh.ParseRecipient,
		func(d string) (age.Recipient, error) { return age.ParseX25519Recipient(d) },
	}

	privateKeyParsers = []func(string) (age.Identity, error){
		func(d string) (age.Identity, error) { return agessh.ParseIdentity([]byte(d)) },
		func(d string) (age.Identity, error) { return age.ParseX25519Identity(d) },
	}
)

type factory bool

// Factory is the key.Factory implementation for age supported keys.
// It supports:
// - RSA
// - Ed25519
// - X25519
const Factory = factory(true)

var _ key.Factory = Factory

func (factory) GetPublicKey(ctx context.Context, data []byte) (model.PublicKey, error) {
	sdata := string(data)
	for _, f := range publicKeyParsers {
		recipient, err := f(sdata)
		fmt.Println(err)
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

func (factory) GetPrivateKey(ctx context.Context, data []byte) (model.PrivateKey, error) {
	sdata := string(data)
	for _, f := range privateKeyParsers {
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
