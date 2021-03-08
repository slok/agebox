package fs

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/slok/agebox/internal/key"
	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/storage"
)

type keyRepository struct {
	publicKeysPath string
	privateKeyPath string
	keyFactory     key.Factory
	fs             fs.FS
	logger         log.Logger
}

// KeyRepositoryConfig is the configuration of the key repository.
type KeyRepositoryConfig struct {
	PublicKeysPath string
	PrivateKeyPath string
	KeyFactory     key.Factory
	FS             fs.FS
	Logger         log.Logger
}

func (c *KeyRepositoryConfig) defaults() error {
	if c.KeyFactory == nil {
		return fmt.Errorf("key factory is required")
	}

	if filepath.IsAbs(c.PublicKeysPath) {
		return fmt.Errorf("public keys path must be relative to working directory")
	}

	if filepath.IsAbs(c.PrivateKeyPath) {
		return fmt.Errorf("private key path must be relative to working directory")
	}

	if c.FS == nil {
		c.FS = os.DirFS(".")
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "storage.fs.KeyRepostory"})

	return nil
}

// NewKeyRepository returns a new file system based key repository that knows
// how to load keys based on files.
// Public keys will be loaded in a discovery mode.
func NewKeyRepository(config KeyRepositoryConfig) (storage.KeyRepository, error) {
	err := config.defaults()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &keyRepository{
		publicKeysPath: config.PublicKeysPath,
		privateKeyPath: config.PrivateKeyPath,
		keyFactory:     config.KeyFactory,
		fs:             config.FS,
		logger:         config.Logger,
	}, nil
}

func (k keyRepository) ListPublicKeys(ctx context.Context) (*storage.PublicKeyList, error) {
	keys := []model.PublicKey{}
	err := fs.WalkDir(k.fs, k.publicKeysPath, fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := fs.ReadFile(k.fs, path)
		if err != nil {
			return fmt.Errorf("could not load public key %q data from file: %w", path, err)
		}

		key, err := k.keyFactory.GetPublicKey(ctx, data)
		if err != nil {
			return fmt.Errorf("could not load public key in %q: %w", path, err)
		}

		keys = append(keys, key)
		return nil
	}))
	if err != nil {
		return nil, err
	}

	k.logger.WithValues(log.Kv{"keys": len(keys)}).Infof("Loaded public keys")

	return &storage.PublicKeyList{Items: keys}, nil
}

func (k keyRepository) GetPrivateKey(ctx context.Context) (model.PrivateKey, error) {
	data, err := fs.ReadFile(k.fs, k.privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load private key %q data from file: %w", k.privateKeyPath, err)
	}

	key, err := k.keyFactory.GetPrivateKey(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("could not load private key in %q: %w", k.privateKeyPath, err)
	}

	k.logger.Infof("Loaded private key")

	return key, nil
}
