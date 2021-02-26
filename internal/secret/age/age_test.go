package age_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	keyage "github.com/slok/agebox/internal/key/age"
	"github.com/slok/agebox/internal/model"
	secretage "github.com/slok/agebox/internal/secret/age"
)

var (
	publicKey1  = getAgePublicKey("age1cgjxz8zgsd8dw9f7ama6wvnua29nyklaypxvelpuwrw5qlfstdts85rtqg")
	privateKey1 = getAgePrivateKey("AGE-SECRET-KEY-1MJP2LG50T844CDZS2LPLD8P2G6SC36D3TVZ5ETNWYTU2FWFYL4XQUC6NEM")
	publicKey2  = getAgePublicKey("age1wlad4ksjvygkcmnnhe362defpt9kmxr3csj53zh25ec2v6g8sajqw2hhet")
	privateKey2 = getAgePrivateKey("AGE-SECRET-KEY-1NS68LYKHWUK0838ZGHXFPN3N6GVKPCCFDSPXGLYL9YYKJPG9MWFQN9SL5P")
)

func getAgePrivateKey(s string) model.PrivateKey {
	k, _ := keyage.Factory.GetPrivateKey(context.TODO(), []byte(s))
	return k
}

func getAgePublicKey(s string) model.PublicKey {
	k, _ := keyage.Factory.GetPublicKey(context.TODO(), []byte(s))
	return k
}

func TestEncrypter(t *testing.T) {
	tests := map[string]struct {
		publicKeys    []model.PublicKey
		privateKey    model.PrivateKey
		secret        model.Secret
		expSecret     model.Secret
		expEncryptErr bool
		expDecryptErr bool
	}{
		"Encrypting secrets without age public keys should fail.": {
			publicKeys: []model.PublicKey{},
			secret: model.Secret{
				DecryptedData: []byte("this is a test secret"),
			},
			expEncryptErr: true,
		},

		"Encrypting secrets without decrypted data should fail.": {
			publicKeys: []model.PublicKey{publicKey1},
			secret: model.Secret{
				DecryptedData: nil,
			},
			expEncryptErr: true,
		},

		"Decrypting secrets without age private key should fail.": {
			publicKeys: []model.PublicKey{publicKey1},
			secret: model.Secret{
				DecryptedData: []byte("this is a test secret"),
			},
			expDecryptErr: true,
		},

		"Encrypt/decryption should work if the private and public keys are compatible.": {
			publicKeys: []model.PublicKey{publicKey1},
			privateKey: privateKey1,
			secret: model.Secret{
				DecryptedData: []byte("this is a test secret"),
			},
		},

		"Encrypt/decryption should work if the private and public keys are compatible (multiple public keys).": {
			publicKeys: []model.PublicKey{publicKey1, publicKey2},
			privateKey: privateKey2,
			secret: model.Secret{
				DecryptedData: []byte("this is a test secret"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// Test encrypt.
			tmpSecret, err := secretage.Encrypter.Encrypt(context.TODO(), test.secret, test.publicKeys)
			if test.expEncryptErr {
				require.Error(err)
				return
			}

			require.NoError(err)

			// Test decrypt.
			secret := model.Secret{
				EncryptedData: tmpSecret.EncryptedData,
			}
			gotSecret, err := secretage.Encrypter.Decrypt(context.TODO(), secret, test.privateKey)
			if test.expDecryptErr {
				require.Error(err)
				return
			}

			require.NoError(err)

			// Test we have succesfuly encrypted and decrypted obtaining the same data.
			assert.Equal(test.secret.DecryptedData, gotSecret.DecryptedData)
		})
	}
}
