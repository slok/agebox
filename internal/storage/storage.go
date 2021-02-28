package storage

import (
	"context"

	"github.com/slok/agebox/internal/model"
)

// PublicKeyList is a list of public keys.
type PublicKeyList struct {
	Items []model.PublicKey
}

// KeyRepository knows how to deal with stored keys.
type KeyRepository interface {
	ListPublicKeys(ctx context.Context) (*PublicKeyList, error)
	GetPrivateKey(ctx context.Context) (model.PrivateKey, error)
}

// SecretRepository knows how to deal with stored secrets.
type SecretRepository interface {
	GetDecryptedSecret(ctx context.Context, id string) (*model.Secret, error)
	SaveEncryptedSecret(ctx context.Context, secret model.Secret) error
}

// TrackRepository is the repository used to track the secret registry.
type TrackRepository interface {
	GetSecretRegistry(ctx context.Context) (*model.SecretRegistry, error)
	SaveSecretRegistry(ctx context.Context, reg model.SecretRegistry) error
}
