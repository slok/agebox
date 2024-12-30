package fs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/storage"
)

// FileManager knows how to deal with files.
type FileManager interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	WriteFile(ctx context.Context, path string, data []byte) error
	DeleteFile(ctx context.Context, path string) error
	StatFile(ctx context.Context, path string) (os.FileInfo, error)
	WalkDir(ctx context.Context, root string, fn fs.WalkDirFunc) error
}

//go:generate mockery --case underscore --output fsmock --outpkg fsmock --name FileManager

type fileManager bool

func (fileManager) ReadFile(_ context.Context, path string) ([]byte, error) { return os.ReadFile(path) }
func (fileManager) WriteFile(_ context.Context, path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
func (fileManager) DeleteFile(_ context.Context, path string) error { return os.Remove(path) }
func (fileManager) StatFile(_ context.Context, path string) (os.FileInfo, error) {
	return os.Stat(path)
}
func (fileManager) WalkDir(_ context.Context, root string, fn fs.WalkDirFunc) error {
	// Symlinks walkdirs have lots of edge cases so as a middle ground between reliability, simplicity and practicality
	// we will only support first level symlinks (as ~/.ssh being a symlink can be a common use case).
	// More info here: https://github.com/golang/go/issues/49580
	evalRoot, err := filepath.EvalSymlinks(root)
	if err == nil {
		root = evalRoot
	}

	return filepath.WalkDir(root, fn)
}

const defaultFileManager = fileManager(true)

// SecretRepositoryConfig is the configuration of the secret repository.
type SecretRepositoryConfig struct {
	FileExtension string
	FileManager   FileManager
	Logger        log.Logger
}

func (c *SecretRepositoryConfig) defaults() error {
	if c.FileExtension == "" {
		c.FileExtension = ".agebox"
	} else if !strings.HasPrefix(c.FileExtension, ".") {
		c.FileExtension = "." + c.FileExtension
	}

	if c.FileManager == nil {
		c.FileManager = defaultFileManager
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "storage.fs.SecretRepository"})

	return nil
}

type secretRepository struct {
	fileExtension string
	fileManager   FileManager
	logger        log.Logger
}

// NewSecretRepository returns a secretRepository based on a file system.
// The secrets IDs are the relative paths without the extension.
func NewSecretRepository(config SecretRepositoryConfig) (storage.SecretRepository, error) {
	err := config.defaults()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return secretRepository{
		fileExtension: config.FileExtension,
		fileManager:   config.FileManager,
		logger:        config.Logger,
	}, nil
}

func (s secretRepository) GetDecryptedSecret(ctx context.Context, id string) (*model.Secret, error) {
	// Sanitize path.
	path := strings.TrimSuffix(id, s.fileExtension)

	// Read file.
	data, err := s.fileManager.ReadFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("could not read decrypted %q file: %w", id, err)
	}

	return &model.Secret{
		ID:            path,
		DecryptedData: data,
	}, nil
}

func (s secretRepository) GetEncryptedSecret(ctx context.Context, id string) (*model.Secret, error) {
	// Sanitize path.
	decPath := strings.TrimSuffix(id, s.fileExtension)
	encPath := decPath + s.fileExtension

	// Read file.
	data, err := s.fileManager.ReadFile(ctx, encPath)
	if err != nil {
		return nil, fmt.Errorf("could not read encrypted %q file: %w", id, err)
	}

	return &model.Secret{
		ID:            decPath,
		EncryptedData: data,
	}, nil
}

func (s secretRepository) SaveEncryptedSecret(ctx context.Context, secret model.Secret) error {
	if secret.EncryptedData == nil {
		return fmt.Errorf("no encrypted data on secret")
	}

	// Sanitize paths.
	decPath := strings.TrimSuffix(secret.ID, s.fileExtension)
	encPath := decPath + s.fileExtension

	// Create encrypted file.
	err := s.fileManager.WriteFile(ctx, encPath, secret.EncryptedData)
	if err != nil {
		return fmt.Errorf("could not write encrypted file: %w", err)
	}

	// Delete decrypted file.
	exists, err := s.existsSecret(ctx, decPath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	err = s.fileManager.DeleteFile(ctx, decPath)
	if err != nil {
		return fmt.Errorf("could not delete decrypted file: %w", err)
	}

	return nil
}

func (s secretRepository) SaveDecryptedSecret(ctx context.Context, secret model.Secret) error {
	if secret.DecryptedData == nil {
		return fmt.Errorf("no decrypted data on secret")
	}

	// Sanitize paths.
	decPath := strings.TrimSuffix(secret.ID, s.fileExtension)
	encPath := decPath + s.fileExtension

	// Create decrypted file.
	err := s.fileManager.WriteFile(ctx, decPath, secret.DecryptedData)
	if err != nil {
		return fmt.Errorf("could not write decrypted file: %w", err)
	}

	// Delete encrypted file if not missing already.
	err = s.ensureFileMissing(ctx, encPath)
	if err != nil {
		return fmt.Errorf("could not delete decrypted file: %w", err)
	}

	return nil
}

func (s secretRepository) ExistsDecryptedSecret(ctx context.Context, id string) (bool, error) {
	return s.existsSecret(ctx, strings.TrimSuffix(id, s.fileExtension))
}

func (s secretRepository) ExistsEncryptedSecret(ctx context.Context, id string) (bool, error) {
	return s.existsSecret(ctx, strings.TrimSuffix(id, s.fileExtension)+s.fileExtension)
}

func (s secretRepository) DeleteDecryptedSecret(ctx context.Context, id string) error {
	decPath := strings.TrimSuffix(id, s.fileExtension)

	err := s.ensureFileMissing(ctx, decPath)
	if err != nil {
		return fmt.Errorf("could not delete decrypted file: %w", err)
	}

	return nil
}

func (s secretRepository) DeleteEncryptedSecret(ctx context.Context, id string) error {
	encPath := strings.TrimSuffix(id, s.fileExtension) + s.fileExtension

	err := s.ensureFileMissing(ctx, encPath)
	if err != nil {
		return fmt.Errorf("could not delete encrypted file: %w", err)
	}

	return nil
}

// deletes file if not missing already.
func (s secretRepository) ensureFileMissing(ctx context.Context, path string) error {
	exists, err := s.existsSecret(ctx, path)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	err = s.fileManager.DeleteFile(ctx, path)
	if err != nil {
		return fmt.Errorf("could not delete file: %w", err)
	}

	return nil
}

func (s secretRepository) existsSecret(ctx context.Context, id string) (bool, error) {
	_, err := s.fileManager.StatFile(ctx, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
