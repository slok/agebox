package cat_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/slok/agebox/internal/box/cat"
	"github.com/slok/agebox/internal/box/cat/catmock"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/encrypt/encryptmock"
	"github.com/slok/agebox/internal/secret/process/processmock"
	"github.com/slok/agebox/internal/storage"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestCatBox(t *testing.T) {
	type mocks struct {
		mpr *catmock.SecretPrinter
		mkr *storagemock.KeyRepository
		msr *storagemock.SecretRepository
		me  *encryptmock.Encrypter
		msp *processmock.IDProcessor
	}

	tests := map[string]struct {
		req    cat.CatBoxRequest
		mock   func(m mocks)
		expErr bool
	}{
		"If no secrets are request it should fail.": {
			req:    cat.CatBoxRequest{},
			mock:   func(m mocks) {},
			expErr: true,
		},

		"Having an error while processing a secret ID, should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having an error while retrieving private key, it should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Decrypting correctly and encrypted secrets should cat the decrypted secrets.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(true, nil)

					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test1")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.mpr.On("PrintSecret", mock.Anything, &secretb).Once().Return(nil)
				}
			},
		},

		"Decrypting correctly and decrypted secrets should cat the secret as it is.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(false, nil)

					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					m.mpr.On("PrintSecret", mock.Anything, &secret).Once().Return(nil)
				}
			},
		},

		"Ignoring secrets after a validation shouldn't use the ignored secrets.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1", "ignored"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "ignored").Once().Return("", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(true, nil)

					secret := model.Secret{EncryptedData: []byte("test1")}
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&secret, nil)

					secretb := model.Secret{DecryptedData: []byte("test1")}
					m.me.On("Decrypt", mock.Anything, secret, mock.Anything).Once().Return(&secretb, nil)

					m.mpr.On("PrintSecret", mock.Anything, &secretb).Once().Return(nil)
				}
			},
		},

		"Having an error while checking secret exists, should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(false, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},

		"Having an error while getting encrypted secrets should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(true, nil)
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(nil, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},

		"Having an error while getting dencrypted secrets should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(false, nil)
					m.msr.On("GetDecryptedSecret", mock.Anything, "secret1").Once().Return(nil, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},

		"Having an error while decrypting secrets should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(true, nil)
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&model.Secret{}, nil)
					m.me.On("Decrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
				}
			},
			expErr: true,
		},

		"Having an error while printing the secret should fail.": {
			req: cat.CatBoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.mkr.On("ListPrivateKeys", mock.Anything).Once().Return(&storage.PrivateKeyList{}, nil)

				// Processed secret.
				{
					m.msr.On("ExistsEncryptedSecret", mock.Anything, "secret1").Once().Return(true, nil)
					m.msr.On("GetEncryptedSecret", mock.Anything, "secret1").Once().Return(&model.Secret{}, nil)
					m.me.On("Decrypt", mock.Anything, mock.Anything, mock.Anything).Once().Return(&model.Secret{}, nil)
					m.mpr.On("PrintSecret", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
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
				mpr: &catmock.SecretPrinter{},
				mkr: &storagemock.KeyRepository{},
				msr: &storagemock.SecretRepository{},
				me:  &encryptmock.Encrypter{},
				msp: &processmock.IDProcessor{},
			}
			test.mock(m)

			// Prepare and execute.
			config := cat.ServiceConfig{
				KeyRepo:           m.mkr,
				SecretRepo:        m.msr,
				Encrypter:         m.me,
				SecretIDProcessor: m.msp,
				SecretPrinter:     m.mpr,
			}
			svc, err := cat.NewService(config)
			require.NoError(err)
			err = svc.CatBox(context.TODO(), test.req)

			// Check.
			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}

			m.mpr.AssertExpectations(t)
			m.mkr.AssertExpectations(t)
			m.msr.AssertExpectations(t)
			m.me.AssertExpectations(t)
			m.msp.AssertExpectations(t)
		})
	}
}
