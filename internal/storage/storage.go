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

//go:generate mockery --case underscore --output storagemock --outpkg storagemock --name KeyRepository

// SecretRepository knows how to deal with stored secrets.
type SecretRepository interface {
	GetDecryptedSecret(ctx context.Context, id string) (*model.Secret, error)
	GetEncryptedSecret(ctx context.Context, id string) (*model.Secret, error)
	SaveEncryptedSecret(ctx context.Context, secret model.Secret) error
	SaveDecryptedSecret(ctx context.Context, secret model.Secret) error
	ExistsDecryptedSecret(ctx context.Context, id string) (bool, error)
	ExistsEncryptedSecret(ctx context.Context, id string) (bool, error)
	DeleteDecryptedSecret(ctx context.Context, id string) error
	DeleteEncryptedSecret(ctx context.Context, id string) error
}

//go:generate mockery --case underscore --output storagemock --outpkg storagemock --name SecretRepository

// TrackRepository is the repository used to track the secret registry.
type TrackRepository interface {
	GetSecretRegistry(ctx context.Context) (*model.SecretRegistry, error)
	SaveSecretRegistry(ctx context.Context, reg model.SecretRegistry) error
}

//go:generate mockery --case underscore --output storagemock --outpkg storagemock --name TrackRepository
