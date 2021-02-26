package key

import (
	"context"

	"github.com/slok/agebox/internal/model"
)

// Factory knows how to load and map raw data to obtain the app model asymmetric keys.
type Factory interface {
	GetPublicKey(ctx context.Context, data []byte) (model.PublicKey, error)
	GetPrivateKey(ctx context.Context, data []byte) (model.PrivateKey, error)
}

//go:generate mockery --case underscore --output keymock --outpkg keymock --name Factory
