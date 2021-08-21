package untrack_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/slok/agebox/internal/box/untrack"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/secret/process/processmock"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestUntrackBox(t *testing.T) {
	type mocks struct {
		msr *storagemock.SecretRepository
		mtr *storagemock.TrackRepository
		msp *processmock.IDProcessor
	}

	tests := map[string]struct {
		req    untrack.BoxRequest
		mock   func(m mocks)
		expErr bool
	}{
		"If no secrets are request it should fail.": {
			req:    untrack.BoxRequest{},
			mock:   func(m mocks) {},
			expErr: true,
		},

		"Having an error while processing a secret ID, should fail.": {
			req: untrack.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Untracking a secret should remove from the tracked ones.": {
			req: untrack.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)

				reg := &model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret1": {},
					"secret2": {},
				}}
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(reg, nil)

				// Should be removed.
				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret2": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)
			},
		},

		"Having an error while saving the tracked secret rgistry should fail.": {
			req: untrack.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, mock.Anything).Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Ignoring secrets after a validation shouldn't use the ignored secrets.": {
			req: untrack.BoxRequest{
				SecretIDs: []string{"secret1", "ignored"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "ignored").Once().Return("", nil)

				reg := &model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret1": {},
					"secret2": {},
				}}
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(reg, nil)

				// Should be removed.
				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret2": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)

			},
		},

		"Getting an error while getting the tracked secret registries, should fail.": {
			req: untrack.BoxRequest{
				SecretIDs: []string{"secret1"},
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, mock.Anything).Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Untracking a secret with deletion should remove from the tracked ones and ensure files are removed.": {
			req: untrack.BoxRequest{
				SecretIDs:       []string{"secret1"},
				DeleteUntracked: true,
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)

				reg := &model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret1": {},
					"secret2": {},
				}}
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(reg, nil)

				// Should remove secrets.
				{
					m.msr.On("DeleteDecryptedSecret", mock.Anything, "secret1").Once().Return(nil)
					m.msr.On("DeleteEncryptedSecret", mock.Anything, "secret1").Once().Return(nil)
				}

				// Should be removed.
				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret2": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)
			},
		},

		"Having an error while deleting decrypted secret should fail.": {
			req: untrack.BoxRequest{
				SecretIDs:       []string{"secret1"},
				DeleteUntracked: true,
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, mock.Anything).Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.msr.On("DeleteDecryptedSecret", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(nil)
			},
			expErr: true,
		},

		"Having an error while deleting encrypted secret should fail.": {
			req: untrack.BoxRequest{
				SecretIDs:       []string{"secret1"},
				DeleteUntracked: true,
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, mock.Anything).Once().Return("secret1", nil)
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(&model.SecretRegistry{EncryptedSecrets: map[string]struct{}{}}, nil)
				m.msr.On("DeleteDecryptedSecret", mock.Anything, mock.Anything).Once().Return(nil)
				m.msr.On("DeleteEncryptedSecret", mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
				m.mtr.On("SaveSecretRegistry", mock.Anything, mock.Anything).Once().Return(nil)
			},
			expErr: true,
		},

		"Failing processing a secret shouldnt affect others and fail.": {
			req: untrack.BoxRequest{
				SecretIDs: []string{
					"secret1",
					"wrongsecret",
					"secret2",
				},
				DeleteUntracked: true,
			},
			mock: func(m mocks) {
				m.msp.On("ProcessID", mock.Anything, "secret1").Once().Return("secret1", nil)
				m.msp.On("ProcessID", mock.Anything, "wrongsecret").Once().Return("wrongsecret", nil)
				m.msp.On("ProcessID", mock.Anything, "secret2").Once().Return("secret2", nil)

				reg := &model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret0":     {},
					"secret1":     {},
					"secret2":     {},
					"secret3":     {},
					"wrongsecret": {},
				}}
				m.mtr.On("GetSecretRegistry", mock.Anything).Once().Return(reg, nil)

				{
					m.msr.On("DeleteDecryptedSecret", mock.Anything, "secret1").Once().Return(nil)
					m.msr.On("DeleteEncryptedSecret", mock.Anything, "secret1").Once().Return(nil)
				}

				{
					m.msr.On("DeleteDecryptedSecret", mock.Anything, "wrongsecret").Once().Return(fmt.Errorf("something"))
				}

				{
					m.msr.On("DeleteDecryptedSecret", mock.Anything, "secret2").Once().Return(nil)
					m.msr.On("DeleteEncryptedSecret", mock.Anything, "secret2").Once().Return(nil)
				}

				expTracked := model.SecretRegistry{EncryptedSecrets: map[string]struct{}{
					"secret0":     {},
					"secret3":     {},
					"wrongsecret": {},
				}}
				m.mtr.On("SaveSecretRegistry", mock.Anything, expTracked).Once().Return(nil)
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
				msr: &storagemock.SecretRepository{},
				mtr: &storagemock.TrackRepository{},
				msp: &processmock.IDProcessor{},
			}
			test.mock(m)

			// Prepare and execute.
			config := untrack.ServiceConfig{
				SecretRepo:        m.msr,
				TrackRepo:         m.mtr,
				SecretIDProcessor: m.msp,
			}
			svc, err := untrack.NewService(config)
			require.NoError(err)
			err = svc.UntrackBox(context.TODO(), test.req)

			// Check.
			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}

			m.msr.AssertExpectations(t)
			m.mtr.AssertExpectations(t)
			m.msp.AssertExpectations(t)
		})
	}
}
