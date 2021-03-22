package age

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"filippo.io/age"

	internalerrors "github.com/slok/agebox/internal/errors"
	keyage "github.com/slok/agebox/internal/key/age"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt"
)

type encrypter bool

// Encrypter is the secret.Encrypter implementation for age encrypt/decrypt algorithm.
// This encrypter is coupled to age keys, so it should be used with age based keys.
const Encrypter = encrypter(true)

var _ encrypt.Encrypter = Encrypter

func (encrypter) Encrypt(ctx context.Context, secret model.Secret, keys []model.PublicKey) (*model.Secret, error) {
	if secret.DecryptedData == nil {
		return nil, internalerrors.ErrNotDecrypted
	}

	ageRecipients := make([]age.Recipient, 0, len(keys))
	for _, k := range keys {
		// Get age compatible key.
		var aKey keyage.PublicKey
		switch v := k.(type) {
		case *keyage.PublicKey:
			aKey = *v
		case keyage.PublicKey:
			aKey = v
		default:
			return nil, fmt.Errorf("invalid public key: %w", internalerrors.ErrNotAgeKey)
		}
		ageRecipients = append(ageRecipients, aKey.AgeRecipient())
	}

	// Age has a decrypt limit of 20 recipients.
	// We don't want the user to encrypt as if this would be ok and then the user
	// have errors decrypting. More information:
	// 	- https://github.com/FiloSottile/age/blob/dabc470bfe8fd14ef93dd83e769e609176af461c/age.go#L171
	//  - https://github.com/FiloSottile/age/issues/139
	const maxAgeRecipients = 20
	if len(ageRecipients) > maxAgeRecipients {
		return nil, fmt.Errorf("age has a max recipients (20) decrypt limit, avoid encrypting")
	}

	// Encrypt data.
	var b bytes.Buffer
	cryptedW, err := age.Encrypt(&b, ageRecipients...)
	if err != nil {
		return nil, fmt.Errorf("age could not prepare secret encrypt: %w", err)
	}

	_, err = io.WriteString(cryptedW, string(secret.DecryptedData))
	if err != nil {
		return nil, fmt.Errorf("could not to encrypt secret: %w", err)
	}
	err = cryptedW.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close encrypted blob: %w", err)
	}

	secret.EncryptedData = b.Bytes()

	return &secret, nil
}
func (encrypter) Decrypt(ctx context.Context, secret model.Secret, key model.PrivateKey) (*model.Secret, error) {
	if secret.EncryptedData == nil {
		return nil, internalerrors.ErrNotEncrypted
	}

	// Get age compatible key.
	var aKey keyage.PrivateKey
	switch v := key.(type) {
	case *keyage.PrivateKey:
		aKey = *v
	case keyage.PrivateKey:
		aKey = v
	default:
		return nil, fmt.Errorf("invalid private key: %w", internalerrors.ErrNotAgeKey)
	}

	// Decrypt data.
	r, err := age.Decrypt(bytes.NewReader(secret.EncryptedData), aKey.AgeIdentity())
	if err != nil {
		return nil, fmt.Errorf("age could not decrypt the secret: %w", err)
	}
	secret.DecryptedData, err = io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve decrypted data: %w", err)
	}

	return &secret, nil
}
