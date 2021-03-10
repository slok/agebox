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
// | !forceDecrypt    | No        | Yes       | Ignore |
// | forceDecrypt     | No        | Yes       | Error  |
// | !forceDecrypt    | Yes       | Yes       | Ignore |
// | forceDecrypt     | Yes       | Yes       | Allow  |
func NewDecryptionPathState(forceDecrypt bool, repo storage.SecretRepository, logger log.Logger) IDProcessor {
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
		case encOK && decOK && !forceDecrypt:
			// Already decrypted, ignore.
			logger.Warningf("Ignoring secret, already decrypted")
			return "", nil
		case encOK && decOK && forceDecrypt:
			// Already decrypted, however we don't care, allow decrypting.
			return secretID, nil
		case encOK && !decOK:
			// Allow decrypting.
			return secretID, nil
		case !encOK && decOK && !forceDecrypt:
			// Already decrypted, ignore.
			logger.Warningf("Ignoring secret, already decrypted")
			return "", nil
		case !encOK && decOK && forceDecrypt:
			// Already decrypted, but we have a force, so we need the encrypted one.
			return "", fmt.Errorf("%q secret missing", secretID)
		case !encOK && !decOK:
			// Everything missing, error.
			return "", fmt.Errorf("%q secret missing", secretID)
		}

		return "", fmt.Errorf("unknown secret state")
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
			logger.Warningf("Ignoring secret, already encrypted")
			return "", nil
		case encOK && !decOK:
			// Already encrypted, ignore.
			logger.Warningf("Ignoring secret, already encrypted")
			return "", nil
		case !encOK && decOK:
			// Allow encrypting.
			return secretID, nil
		case !encOK && !decOK:
			// Everything missing, error.
			return "", fmt.Errorf("%q secret missing", secretID)
		}

		return "", fmt.Errorf("unknown secret state")
	})
}
