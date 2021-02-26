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
