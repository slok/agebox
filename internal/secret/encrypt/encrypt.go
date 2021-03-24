package encrypt

import (
	"context"

	"github.com/slok/agebox/internal/model"
)

// Encrypter knows how to encrypt and decrypt secrets.
type Encrypter interface {
	Encrypt(ctx context.Context, secret model.Secret, keys []model.PublicKey) (*model.Secret, error)
	Decrypt(ctx context.Context, secret model.Secret, keys []model.PrivateKey) (*model.Secret, error)
}

//go:generate mockery --case underscore --output encryptmock --outpkg encryptmock --name Encrypter
