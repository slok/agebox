package encrypt_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/slok/agebox/internal/box/encrypt"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt/encryptmock"
	"github.com/slok/agebox/internal/secret/process/processmock"
	"github.com/slok/agebox/internal/storage"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestEncryptBox(t *testing.T) {
	type mocks struct {
		mkr *storagemock.KeyRepository
		msr *storagemock.SecretRepository
		mtr *storagemock.TrackRepository
		me  *encryptmock.Encrypter
		msp *processmock.IDProcessor
	}

	tests := map[string]struct {
		req    encrypt.BoxRequest
		mock   func(m mocks)
		expErr bool
	}{
		"If no secrets are request it should fail.": {
			req:    encrypt.BoxRequest{},
			mock:   func(m mocks) {},
			expErr: true,
		},

		"Having an error while processing a secret ID, should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", fmt.Errorf("something"))
			},
			expErr: true,
		},
		"Having an error while retrieving secret tracking information, should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having an error while retrieving public keys, it should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Encrypting correctly secrets should encrypt the secrets.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					secret := model.Secret{DecryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("test1")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}

				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret1": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)
			},
		},

		"Ignoring secrets after a validation shouldn't use the ignored secrets.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1", "ignored"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "ignored").Once().Return("", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					secret := model.Secret{DecryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("test1")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}

				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret1": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)
			},
		},

		"Failing processing a secret shouldnt affect others and fail.": {
			req: encrypt.BoxRequest{
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
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Secret 1.
				{
					secret := model.Secret{DecryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("test1")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}

				// Wrong secret.
				{
					m.msr.On("GetDecryptedSecret", mock.Anything, "wrongsecret1").Once().Return(nil, fmt.Errorf("something"))
				}

				// Secret 2.
				{
					secret := model.Secret{DecryptedData: []byte("test2")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret2").Once().Return(&secret, nil)

					secretb := model.Secret{EncryptedData: []byte("test2")}
					m.me.On("Encrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveEncryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}

				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret1": {},
					"secret2": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)
			},
			expErr: true,
		},

		"Having an error while getting decrypted secrets should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetDecryptedSecret", mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
				}

				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(nil)
			},
			expErr: true,
		},

		"Having an error while getting encrypting secrets should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetDecryptedSecret", mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.me.On("Encrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
				}

				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(nil)
			},
			expErr: true,
		},

		"Having an error while getting saving encrypted secrets should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetDecryptedSecret", mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.me.On("Encrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.msr.On("SaveEncryptedSecret", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
				}

				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(nil)
			},
			expErr: true,
		},

		"Having an error while storing the tracking information should fail.": {
			req: encrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mkr.On("ListPublicKeys", mock.Anything).Once().Return(&storage.PublicKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetDecryptedSecret", mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.me.On("Encrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.msr.On("SaveEncryptedSecret", mock.Anything, mock.Anything).Once().Return(nil)
				}

				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
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
				mtr: &storagemock.TrackRepository{},
				me:  &encryptmock.Encrypter{},
				msp: &processmock.IDProcessor{},
			}
			test.mock(m)

			// Prepare and execute.
			config := encrypt.ServiceConfig{
				KeyRepo:           m.mkr,
				SecretRepo:        m.msr,
				TrackRepo:         m.mtr,
				Encrypter:         m.me,
				SecretIDProcessor: m.msp,
			}
			svc, err := encrypt.NewService(config)
			require.NoError(err)
			err = svc.EncryptBox(context.TODO(), test.req)

			// Check.
			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}

			m.mkr.AssertExpectations(t)
			m.msr.AssertExpectations(t)
			m.mtr.AssertExpectations(t)
			m.me.AssertExpectations(t)
			m.msp.AssertExpectations(t)
		})
	}
}
