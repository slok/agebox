package fs

import (
	"context"
	"fmt"
	"sort"

	"github.com/ghodss/yaml"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
)

// TrackRepositoryConfig is the configuration of the tracking repository.
type TrackRepositoryConfig struct {
	FilePath    string
	FileManager FileManager
	Logger      log.Logger
}

func (c *TrackRepositoryConfig) defaults() error {
	if c.FilePath == "" {
		c.FilePath = ".ageboxreg.yml"
	}

	if c.FileManager == nil {
		c.FileManager = defaultFileManager
	}

	if c.Logger == nil {
		c.Logger = log.Noop
	}
	c.Logger = c.Logger.WithValues(log.Kv{"svc": "storage.fs.TrackRepository"})

	return nil
}

// TrackRepository tracks the repository encrypted/decrypted secrets using the File system.
type TrackRepository struct {
	filePath    string
	fileManager FileManager
	logger      log.Logger
}

// NewTrackRepository returns a TrackRepository based on a file system.
func NewTrackRepository(config TrackRepositoryConfig) (*TrackRepository, error) {
	err := config.defaults()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &TrackRepository{
		filePath:    config.FilePath,
		fileManager: config.FileManager,
		logger:      config.Logger,
	}, nil
}

const secretRegistryJSONV1ID = "1"

type secretRegistryJSONV1 struct {
	Version string   `json:"version"`
	FileIDs []string `json:"file_ids"`
}

// GetSecretRegistry gets the secret registry form the file system.
func (t TrackRepository) GetSecretRegistry(ctx context.Context) (*model.SecretRegistry, error) {
	data, err := t.fileManager.ReadFile(ctx, t.filePath)
	if err != nil {
		return nil, fmt.Errorf("could not get secret tracking file %q: %w", t.filePath, err)
	}

	var sr secretRegistryJSONV1
	err = yaml.Unmarshal(data, &sr)
	if err != nil {
		return nil, fmt.Errorf("could not load secret tracking file: %w", err)
	}

	if sr.Version != secretRegistryJSONV1ID {
		return nil, fmt.Errorf("unsupported secret tracking file version: %w", err)
	}

	// Map to model.
	ids := map[string]struct{}{}
	for _, es := range sr.FileIDs {
		ids[es] = struct{}{}
	}

	return &model.SecretRegistry{
		EncryptedSecrets: ids,
	}, nil
}

// SaveSecretRegistry saves the secret registry from the file system.
func (t TrackRepository) SaveSecretRegistry(ctx context.Context, reg model.SecretRegistry) error {
	// TODO(slok): Safer way of replacing file (e.g: https://github.com/google/renameio).

	// Map.
	ids := make([]string, 0, len(reg.EncryptedSecrets))
	for id := range reg.EncryptedSecrets {
		ids = append(ids, id)
	}
	sort.SliceStable(ids, func(i, j int) bool { return ids[i] < ids[j] })

	sr := secretRegistryJSONV1{
		Version: secretRegistryJSONV1ID,
		FileIDs: ids,
	}
	data, err := yaml.Marshal(sr)
	if err != nil {
		return fmt.Errorf("could not marshal to YAML: %w", err)
	}

	err = t.fileManager.WriteFile(ctx, t.filePath, data)
	if err != nil {
		return fmt.Errorf("could write secret tracking file: %w", err)
	}

	return nil
}
