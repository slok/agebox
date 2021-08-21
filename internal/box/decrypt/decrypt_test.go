package decrypt_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/slok/agebox/internal/box/decrypt"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt/encryptmock"
	"github.com/slok/agebox/internal/secret/process/processmock"
	"github.com/slok/agebox/internal/storage"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestDecryptBox(t *testing.T) {
	type mocks struct {
		mkr *storagemock.KeyRepository
		msr *storagemock.SecretRepository
		me  *encryptmock.Encrypter
		msp *processmock.IDProcessor
	}

	tests := map[string]struct {
		req    decrypt.BoxRequest
		mock   func(m mocks)
		expErr bool
	}{
		"If no secrets are request it should fail.": {
			req:    decrypt.BoxRequest{},
			mock:   func(m mocks) {},
			expErr: true,
		},

		"Having an error while processing a secret ID, should fail.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having an error while retrieving private keys, it should fail.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Decrypting correctly secrets should encrypt the secrets.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test1")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveDecryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}
			},
		},

		"Ignoring secrets after a validation shouldn't use the ignored secrets.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1", "ignored"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "ignored").Once().Return("", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test1")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveDecryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}
			},
		},

		"Failing processing a secret shouldnt affect others and fail.": {
			req: decrypt.BoxRequest{
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

				// Secret 1.
				{
					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test1")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveDecryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}

				// Wrong secret.
				{
					m.msr.On("GetEncryptedSecret", mock.Anything, "wrongsecret1").Once().Return(nil, fmt.Errorf("something"))
				}

				// Secret 2.
				{
					secret := model.Secret{EncryptedData: []byte("test2")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret2").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test2")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.msr.On("SaveDecryptedSecret", mock.Anything, secretb).Once().Return(nil)
				}
			},
			expErr: true,
		},

		"Having an error while getting encrypted secrets should fail.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(nil, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},

		"Having an error while getting decrypting secrets should fail.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&model.Secret{}, nil)
					m.me.On("Decrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},

		"Having an error while getting saving decrypted secrets should fail.": {
			req: decrypt.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&model.Secret{}, nil)
					m.me.On("Decrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.msr.On("SaveDecryptedSecret", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
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
			config := decrypt.ServiceConfig{
				KeyRepo:           m.mkr,
				SecretRepo:        m.msr,
				Encrypter:         m.me,
				SecretIDProcessor: m.msp,
			}
			svc, err := decrypt.NewService(config)
			require.NoError(err)
			err = svc.DecryptBox(context.TODO(), test.req)

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
