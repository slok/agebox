package fs

import (
	"context"
	"fmt"
	"io/fs"
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
	fileManager    FileManager
	logger         log.Logger
}

// KeyRepositoryConfig is the configuration of the key repository.
type KeyRepositoryConfig struct {
	PublicKeysPath string
	PrivateKeyPath string
	KeyFactory     key.Factory
	FileManager    FileManager
	Logger         log.Logger
}

func (c *KeyRepositoryConfig) defaults() error {
	if c.KeyFactory == nil {
		return fmt.Errorf("key factory is required")
	}

	c.PublicKeysPath = filepath.Clean(c.PublicKeysPath)
	c.PrivateKeyPath = filepath.Clean(c.PrivateKeyPath)

	if c.FileManager == nil {
		c.FileManager = defaultFileManager
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "storage.fs.KeyRepository"})

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
		fileManager:    config.FileManager,
		logger:         config.Logger,
	}, nil
}

func (k keyRepository) ListPublicKeys(ctx context.Context) (*storage.PublicKeyList, error) {
	keys := []model.PublicKey{}
	err := k.fileManager.WalkDir(ctx, k.publicKeysPath, fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := k.fileManager.ReadFile(ctx, path)
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
	data, err := k.fileManager.ReadFile(ctx, k.privateKeyPath)
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
