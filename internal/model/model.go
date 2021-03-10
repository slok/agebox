package model

// Key represents a security key.
type Key interface {
	Data() []byte
}

// PublicKey represents a public key.
type PublicKey interface {
	Key
	IsPublic()
}

// PrivateKey represents a public key.
type PrivateKey interface {
	Key
	IsPrivate()
}

// Secret represents a secret. If []byte data is nil, it means that the
// data has not been initialized or missing (different from being empty).
type Secret struct {
	ID            string
	EncryptedData []byte
	DecryptedData []byte
}

// SecretRegistry represents the registry of secrets that is used to track
// information about the actions made on secrets.
type SecretRegistry struct {
	EncryptedSecrets map[string]struct{}
}
