package errors

import "errors"

var (
	// ErrNotEncrypted is used when the secret is not encrypted.
	ErrNotEncrypted = errors.New("secret is not encrypted")
	// ErrNotDecrypted is used when the secret is not decrypted.
	ErrNotDecrypted = errors.New("secret is not decrypted")
	// ErrNotAgeKey is used when the the expected key is age compatible and it isn't.
	ErrNotAgeKey = errors.New("key is not age compatible key")
)
