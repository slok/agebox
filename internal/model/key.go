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
