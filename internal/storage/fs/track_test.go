package fs_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/storage/fs"
	"github.com/slok/agebox/internal/storage/fs/fsmock"
)

func TestGetSecretRegistry(t *testing.T) {
	tests := map[string]struct {
		config       fs.TrackRepositoryConfig
		mock         func(mfm *fsmock.FileManager)
		expErr       bool
		expSecretReg model.SecretRegistry
	}{
		"Getting secret tracking file should retrieve the data and map to model correctly.": {
			mock: func(mfm *fsmock.FileManager) {
				ageboxRegYAML := `
version: "1"
file_ids:
  - f1
  - f2
  - a/f3`
				mfm.On("ReadFile", mock.Anything, ".ageboxreg.yml").Once().Return([]byte(ageboxRegYAML), nil)
			},
			expSecretReg: model.SecretRegistry{
				EncryptedSecrets: map[string]struct{}{
					"f1":   {},
					"f2":   {},
					"a/f3": {},
				},
			},
		},

		"An error while reading the tracking fail, should fail.": {
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("ReadFile", mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"An invalid json should fail.": {
			mock: func(mfm *fsmock.FileManager) {
				ageboxRegJSON := `{`
				mfm.On("ReadFile", mock.Anything, mock.Anything).Once().Return([]byte(ageboxRegJSON), nil)
			},
			expErr: true,
		},

		"An invalid tracking file version should fail.": {
			mock: func(mfm *fsmock.FileManager) {
				ageboxRegYAML := `
version: "2"
file_ids:
  - f1
  - f2
  - a/f3`
				mfm.On("ReadFile", mock.Anything, mock.Anything).Once().Return([]byte(ageboxRegYAML), nil)
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// Mock.
			mfm := &fsmock.FileManager{}
			test.mock(mfm)

			// Prepare.
			test.config.FileManager = mfm
			repo, err := fs.NewTrackRepository(test.config)
			require.NoError(err)

			gotSecretReg, err := repo.GetSecretRegistry(context.TODO())

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecretReg, *gotSecretReg)
			}

			mfm.AssertExpectations(t)
		})
	}
}

func TestSaveSecretRegistry(t *testing.T) {
	tests := map[string]struct {
		config    fs.TrackRepositoryConfig
		secretReg model.SecretRegistry
		mock      func(mfm *fsmock.FileManager)
		expErr    bool
	}{
		"Storing the secretReg should be stored correctly and with the encrypted files in order.": {
			secretReg: model.SecretRegistry{
				EncryptedSecrets: map[string]struct{}{
					"f1":   {},
					"a/f3": {},
					"f2":   {},
				},
			},
			mock: func(mfm *fsmock.FileManager) {
				expAgeboxRegJSON := `file_ids:
- a/f3
- f1
- f2
version: "1"
`
				mfm.On("WriteFile", mock.Anything, ".ageboxreg.yml", []byte(expAgeboxRegJSON)).Once().Return(nil)
			},
		},

		"An error storing secret regostry in the file should fail.": {
			secretReg: model.SecretRegistry{
				EncryptedSecrets: map[string]struct{}{},
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, mock.Anything, mock.Anything).Once().Return(fmt.Errorf("something"))
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// Mock.
			mfm := &fsmock.FileManager{}
			test.mock(mfm)

			// Prepare.
			test.config.FileManager = mfm
			repo, err := fs.NewTrackRepository(test.config)
			require.NoError(err)

			err = repo.SaveSecretRegistry(context.TODO(), test.secretReg)

			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}

			mfm.AssertExpectations(t)
		})
	}
}
