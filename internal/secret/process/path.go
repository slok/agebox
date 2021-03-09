package process

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/storage"
)

// NewPathSanitizer knows how to sanitize a path for a secret returning
// always the original path in a sane way.
func NewPathSanitizer(encryptExt string) IDProcessor {
	if encryptExt == "" {
		encryptExt = ".agebox"
	} else if !strings.HasPrefix(encryptExt, ".") {
		encryptExt = "." + encryptExt
	}

	return IDProcessorFunc(func(_ context.Context, secretID string) (string, error) {
		// Fix prefix.
		secretID = strings.TrimSuffix(secretID, encryptExt)

		// Sanitize full path.
		return filepath.Clean(secretID), nil
	})
}

// NewDecryptionPathState checks the state of the files on a decryption is correct.
// the result is based on the different secret files status (decrypted and encrypted).
//
// | opts             | Encrypted | Decrypted | Result |
// |------------------|-----------|-----------|--------|
// |                  | No        | No        | Error  |
// |                  | Yes       | No        | Allow  |
// |                  | No        | Yes       | Ignore |
// | ignoreBothExists | Yes       | Yes       | Ignore |
// |                  | Yes       | Yes       | Allow  |
func NewDecryptionPathState(ignoreBothExists bool, repo storage.SecretRepository, logger log.Logger) IDProcessor {
	return IDProcessorFunc(func(ctx context.Context, secretID string) (string, error) {
		encOK, err := repo.ExistsEncryptedSecret(ctx, secretID)
		if err != nil {
			return "", fmt.Errorf("could not check encrypted secret exists: %w", err)
		}

		decOK, err := repo.ExistsDecryptedSecret(ctx, secretID)
		if err != nil {
			return "", fmt.Errorf("could not check decrypted secret exists: %w", err)
		}

		logger := logger.WithValues(log.Kv{"secret-id": secretID})

		switch {
		case encOK && decOK && ignoreBothExists:
			// Already decrypted, ignore.
			logger.Warningf("ignoring secret, already decrypted")
			return "", nil
		case encOK && decOK && !ignoreBothExists:
			// Already decrypted, however we don't care, allow decrypting.
			return secretID, nil
		case encOK && !decOK:
			// Allow decrypting.
			return secretID, nil
		case !encOK && decOK:
			// Already decrypted, ignore.
			logger.Warningf("ignoring secret, already decrypted")
			return "", nil
		}

		return "", fmt.Errorf("%q secret missing", secretID)
	})
}

// NewEncryptionPathState checks the state of the files on a encryption is correct.
// the result is based on the different secret files status (decrypted and encrypted).
//
// | opts | Encrypted | Decrypted | Result |
// |------|-----------|-----------|--------|
// |      | No        | No        | Error  |
// |      | Yes       | No        | Ignore |
// |      | No        | Yes       | Allow  |
// |      | Yes       | Yes       | Ignore |
func NewEncryptionPathState(repo storage.SecretRepository, logger log.Logger) IDProcessor {
	return IDProcessorFunc(func(ctx context.Context, secretID string) (string, error) {
		encOK, err := repo.ExistsEncryptedSecret(ctx, secretID)
		if err != nil {
			return "", fmt.Errorf("could not check decrypted secret exists: %w", err)
		}

		decOK, err := repo.ExistsDecryptedSecret(ctx, secretID)
		if err != nil {
			return "", fmt.Errorf("could not check decrypted secret exists: %w", err)
		}

		logger := logger.WithValues(log.Kv{"secret-id": secretID})

		switch {
		case encOK && decOK:
			// Already encrypted, ignore.
			logger.Warningf("ignoring secret, already encrypted")
			return "", nil
		case encOK && !decOK:
			// Already encrypted, ignore.
			logger.Warningf("ignoring secret, already encrypted")
			return "", nil
		case !encOK && decOK:
			// Allow encrypting.
			return secretID, nil
		}

		return "", fmt.Errorf("%q secret missing", secretID)
	})
}
