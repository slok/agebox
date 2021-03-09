package storage

import (
	"context"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/model"
)

// We are not using anonymous composition in the repository because we want
// to fail when we are adding a new method to the interface so we don't use
// a write real implementation operation/method of the wrapped repository
// as a side effect.
type dryRunSecretRepository struct {
	logger log.Logger
	repo   SecretRepository
}

// NewDryRunSecretRepository returns a secret repositpory that can be used as a dry-run
// it will have all the Read operations and remove the write operations.
func NewDryRunSecretRepository(logger log.Logger, repo SecretRepository) SecretRepository {
	return &dryRunSecretRepository{
		logger: logger.WithValues(log.Kv{"svc": "storage.dryRunSecretRepository"}),
		repo:   repo,
	}
}

func (d dryRunSecretRepository) GetDecryptedSecret(ctx context.Context, id string) (*model.Secret, error) {
	return d.repo.GetDecryptedSecret(ctx, id)
}

func (d dryRunSecretRepository) GetEncryptedSecret(ctx context.Context, id string) (*model.Secret, error) {
	return d.repo.GetEncryptedSecret(ctx, id)
}

func (d dryRunSecretRepository) SaveEncryptedSecret(ctx context.Context, secret model.Secret) error {
	d.logger.WithValues(log.Kv{"secret-id": secret.ID}).
		Warningf("Not saving encrypted secret (dry-run)")
	return nil
}

func (d dryRunSecretRepository) SaveDecryptedSecret(ctx context.Context, secret model.Secret) error {
	d.logger.WithValues(log.Kv{"secret-id": secret.ID}).
		Warningf("Not saving decrypted secret (dry-run)")
	return nil
}

func (d dryRunSecretRepository) ExistsDecryptedSecret(ctx context.Context, id string) (bool, error) {
	return d.repo.ExistsDecryptedSecret(ctx, id)
}

func (d dryRunSecretRepository) ExistsEncryptedSecret(ctx context.Context, id string) (bool, error) {
	return d.repo.ExistsEncryptedSecret(ctx, id)
}

// We are not using anonymous composition in the repository because we want
// to fail when we are adding a new method to the interface so we don't use
// a write real implementation operation/method of the wrapped repository
// as a side effect.
type dryRunKeyRepository struct {
	logger log.Logger
	repo   KeyRepository
}

// NewDryRunKeyRepository returns a key repository that can be used as a dry-run
// it will have all the Read operations and remove the write operations.
func NewDryRunKeyRepository(logger log.Logger, repo KeyRepository) KeyRepository {
	return &dryRunKeyRepository{
		logger: logger.WithValues(log.Kv{"svc": "storage.dryRunKeyRepository"}),
		repo:   repo,
	}
}

func (d dryRunKeyRepository) ListPublicKeys(ctx context.Context) (*PublicKeyList, error) {
	return d.repo.ListPublicKeys(ctx)
}

func (d dryRunKeyRepository) GetPrivateKey(ctx context.Context) (model.PrivateKey, error) {
	return d.repo.GetPrivateKey(ctx)
}

// We are not using anonymous composition in the repository because we want
// to fail when we are adding a new method to the interface so we don't use
// a write real implementation operation/method of the wrapped repository
// as a side effect.
type dryRunTrackRepository struct {
	logger log.Logger
	repo   TrackRepository
}

// NewDryRunTrackRepository returns a tracking repositpory that can be used as a dry-run
// it will have all the Read operations and remove the write operations.
func NewDryRunTrackRepository(logger log.Logger, repo TrackRepository) TrackRepository {
	return &dryRunTrackRepository{
		logger: logger.WithValues(log.Kv{"svc": "storage.dryRunTrackRepository"}),
		repo:   repo,
	}
}

func (d *dryRunTrackRepository) GetSecretRegistry(ctx context.Context) (*model.SecretRegistry, error) {
	return d.repo.GetSecretRegistry(ctx)
}

func (d *dryRunTrackRepository) SaveSecretRegistry(ctx context.Context, reg model.SecretRegistry) error {
	d.logger.Warningf("Not saving secret tracking (dry-run)")
	return nil
}
