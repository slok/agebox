package reencrypt_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/slok/agebox/internal/box/reencrypt"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt/encryptmock"
	"github.com/slok/agebox/internal/secret/process/processmock"
	"github.com/slok/agebox/internal/storage"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestReencryptBox(t *testing.T) {
	type mocks struct {
		mkr *storagemock.KeyRepository
		msr *storagemock.SecretRepository
		me  *encryptmock.Encrypter
		msp *processmock.IDProcessor
	}

	tests := map[string]struct {
		req    reencrypt.BoxRequest
		mock   func(m mocks)
		expErr bool
	}{
		"If no secrets are requesed it should fail.": {
			req:    reencrypt.BoxRequest{},
			mock:   func(m mocks) {},
			expErr: true,
		},

		"Having an error while processing a secret ID, should fail.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having an error while retrieving private key, it should fail.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having an error while retrieving public keys, it should fail.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Reencrypting an already encrypted secret, should decrypt and encrypt.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(true, nil)

					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test1")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					secretc := model.Secret{EncryptedData: []byte("retest1")}
					m.me.On("Encrypt", mock.Anything, secretb, mock.Anything).Once().Return(&secretc, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretc).Once().Return(nil)
				}

			},
		},

		"Reencrypting an already decrypted secret, should only encrypt.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(false, nil)

					secret := model.Secret{DecryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("retest1")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}
			},
		},

		"Ignoring secrets after a validation shouldn't use the ignored secrets.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{"secret1", "ignored"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "ignored").Once().Return("", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(false, nil)

					secret := model.Secret{DecryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("retest1")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}
			},
		},

		"Failing processing a secret should stop and fail the process.": {
			req: reencrypt.BoxRequest{
				SecretIDs: []string{
					"secret1",
					"wrongsecret1",
					"secret2",
				},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "wrongsecret1").Once().Return("wrongsecret1", nil)
				m.msp.On("ProcessID", mock.Anything, "secret2").Once().Return("secret2", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Secret 1.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(false, nil)

					secret := model.Secret{DecryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("retest1")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}

				// Wrong secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "wrongsecret1").Once().Return(false, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// Mocks.
			m := mocks{
				mkr: &storagemock.KeyRepository{},
				msr: &storagemock.SecretRepository{},
				me:  &encryptmock.Encrypter{},
				msp: &processmock.IDProcessor{},
			}
			test.mock(m)

			// Prepare and execute.
			config := reencrypt.ServiceConfig{
				KeyRepo:           m.mkr,
				SecretRepo:        m.msr,
				Encrypter:         m.me,
				SecretIDProcessor: m.msp,
			}
			svc, err := reencrypt.NewService(config)
			require.NoError(err)
			err = svc.ReencryptBox(context.TODO(), test.req)

			// Check.
			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}

			m.mkr.AssertExpectations(t)
			m.msr.AssertExpectations(t)
			m.me.AssertExpectations(t)
			m.msp.AssertExpectations(t)
		})
	}
}
