package fs

import (
	"bufio"
	"bytes"
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
	publicKeysPath  string
	privateKeysPath string
	keyFactory      key.Factory
	fileManager     FileManager
	logger          log.Logger
}

// KeyRepositoryConfig is the configuration of the key repository.
type KeyRepositoryConfig struct {
	PublicKeysPath  string
	PrivateKeysPath string
	KeyFactory      key.Factory
	FileManager     FileManager
	Logger          log.Logger
}

func (c *KeyRepositoryConfig) defaults() error {
	if c.KeyFactory == nil {
		return fmt.Errorf("key factory is required")
	}

	c.PublicKeysPath = filepath.Clean(c.PublicKeysPath)
	c.PrivateKeysPath = filepath.Clean(c.PrivateKeysPath)

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
		publicKeysPath:  config.PublicKeysPath,
		privateKeysPath: config.PrivateKeysPath,
		keyFactory:      config.KeyFactory,
		fileManager:     config.FileManager,
		logger:          config.Logger,
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

		// Read key file.
		data, err := k.fileManager.ReadFile(ctx, path)
		if err != nil {
			return fmt.Errorf("could not read public key %q data from file: %w", path, err)
		}

		// Just in case we have multiple keys in the file (one per line).
		dataLines, err := splitLines(data)
		if err != nil {
			return fmt.Errorf("could not split key data by lines: %w", err)
		}

		for _, data := range dataLines {
			key, err := k.keyFactory.GetPublicKey(ctx, data)
			if err != nil {
				// If we can't load a key, don't fail, we try our best.
				k.logger.WithValues(log.Kv{"key": path}).Warningf("Could not load public key: %s", err)
				continue
			}

			keys = append(keys, key)
		}

		return nil
	}))
	if err != nil {
		return nil, err
	}

	k.logger.WithValues(log.Kv{"keys": len(keys)}).Infof("Loaded public keys")

	return &storage.PublicKeyList{Items: keys}, nil
}

func (k keyRepository) ListPrivateKeys(ctx context.Context) (*storage.PrivateKeyList, error) {
	keys := []model.PrivateKey{}
	err := k.fileManager.WalkDir(ctx, k.privateKeysPath, fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// TODO(slok): Think if we need to ignore .pub files.

		// Read key file.
		data, err := k.fileManager.ReadFile(ctx, path)
		if err != nil {
			return fmt.Errorf("could not read private key %q data from file: %w", path, err)
		}

		key, err := k.keyFactory.GetPrivateKey(ctx, data)
		if err != nil {
			// If we can't load a key, don't fail, we try our best.
			k.logger.WithValues(log.Kv{"key": path}).Warningf("Could not load private key: %s", err)
			return nil
		}

		keys = append(keys, key)

		return nil
	}))
	if err != nil {
		return nil, err
	}

	k.logger.WithValues(log.Kv{"keys": len(keys)}).Infof("Loaded private keys")

	return &storage.PrivateKeyList{Items: keys}, nil
}

func (k keyRepository) GetPrivateKey(ctx context.Context) (model.PrivateKey, error) {
	data, err := k.fileManager.ReadFile(ctx, k.privateKeysPath)
	if err != nil {
		return nil, fmt.Errorf("could not load private key %q data from file: %w", k.privateKeysPath, err)
	}

	key, err := k.keyFactory.GetPrivateKey(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("could not load private key in %q: %w", k.privateKeysPath, err)
	}

	k.logger.Infof("Loaded private key")

	return key, nil
}

// splitLines will split lines and remove empty and `#` comment lines.
func splitLines(d []byte) ([][]byte, error) {
	lines := [][]byte{}
	sc := bufio.NewScanner(bytes.NewReader(d))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}

		lines = append(lines, line)
	}

	err := sc.Err()
	if err != nil {
		return nil, err
	}

	return lines, nil
}
