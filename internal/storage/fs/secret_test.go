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

func TestGetDecryptedSecret(t *testing.T) {
	tests := map[string]struct {
		config    fs.SecretRepositoryConfig
		path      string
		mock      func(mfm *fsmock.FileManager)
		expErr    bool
		expSecret model.Secret
	}{
		"Decrypted secrets should get the file without extension correctly.": {
			path: "secrets/app1/secret1.yaml",
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("ReadFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return([]byte("dec1"), nil)
			},
			expSecret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				DecryptedData: []byte("dec1"),
			},
		},

		"Having an error while reading the file should fail.": {
			path: "secrets/app1/secret1.yaml",
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("ReadFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"The path received for the secret should be sanitized (default extension).": {
			path: "secrets/app1/secret1.yaml.agebox",
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("ReadFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return([]byte("dec1"), nil)
			},
			expSecret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				DecryptedData: []byte("dec1"),
			},
		},

		"The path received for the secret should be sanitized (custom extension).": {
			config: fs.SecretRepositoryConfig{
				FileExtension: "test",
			},
			path: "secrets/app1/secret1.yaml.test",
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("ReadFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return([]byte("dec1"), nil)
			},
			expSecret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				DecryptedData: []byte("dec1"),
			},
		},

		"The path received for the secret should be sanitized (custom extension with dot).": {
			config: fs.SecretRepositoryConfig{
				FileExtension: ".test",
			},
			path: "secrets/app1/secret1.yaml.test",
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("ReadFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return([]byte("dec1"), nil)
			},
			expSecret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				DecryptedData: []byte("dec1"),
			},
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
			repo, err := fs.NewSecretRepository(test.config)
			require.NoError(err)

			gotSecret, err := repo.GetDecryptedSecret(context.TODO(), test.path)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, *gotSecret)
			}

			mfm.AssertExpectations(t)
		})
	}
}

func TestSaveEncryptedSecret(t *testing.T) {
	tests := map[string]struct {
		config fs.SecretRepositoryConfig
		secret model.Secret
		mock   func(mfm *fsmock.FileManager)
		expErr bool
	}{
		"Saving an encrypted secret should store the encrypted and remove the decrypted (default extension).": {
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				EncryptedData: []byte("enc1"),
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, "secrets/app1/secret1.yaml.agebox", []byte("enc1")).Once().Return(nil)
				mfm.On("DeleteFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return(nil)
			},
		},

		"Saving an encrypted secret should store the encrypted and remove the decrypted (custom extension).": {
			config: fs.SecretRepositoryConfig{
				FileExtension: "test",
			},
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				EncryptedData: []byte("enc1"),
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, "secrets/app1/secret1.yaml.test", []byte("enc1")).Once().Return(nil)
				mfm.On("DeleteFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return(nil)
			},
		},

		"Saving an encrypted secret should store the encrypted and remove the decrypted (custom extension with dot).": {
			config: fs.SecretRepositoryConfig{
				FileExtension: ".test",
			},
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				EncryptedData: []byte("enc1"),
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, "secrets/app1/secret1.yaml.test", []byte("enc1")).Once().Return(nil)
				mfm.On("DeleteFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return(nil)
			},
		},

		"Saving an encrypted secret without encrypted data should fail.": {
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				DecryptedData: []byte("enc1"),
			},
			mock:   func(mfm *fsmock.FileManager) {},
			expErr: true,
		},

		"Having an error while saving the encrypted data,s hould fail and don't delete the decrypted file.": {
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				EncryptedData: []byte("enc1"),
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, "secrets/app1/secret1.yaml.agebox", []byte("enc1")).Once().Return(fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having an error while deleting the encrypted data, should fail.": {
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml",
				EncryptedData: []byte("enc1"),
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, "secrets/app1/secret1.yaml.agebox", []byte("enc1")).Once().Return(nil)
				mfm.On("DeleteFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return(fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Paths should be sanitized correctly in case there don't have the correct extension.": {
			secret: model.Secret{
				ID:            "secrets/app1/secret1.yaml.agebox",
				EncryptedData: []byte("enc1"),
			},
			mock: func(mfm *fsmock.FileManager) {
				mfm.On("WriteFile", mock.Anything, "secrets/app1/secret1.yaml.agebox", []byte("enc1")).Once().Return(nil)
				mfm.On("DeleteFile", mock.Anything, "secrets/app1/secret1.yaml").Once().Return(nil)
			},
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
			repo, err := fs.NewSecretRepository(test.config)
			require.NoError(err)

			err = repo.SaveEncryptedSecret(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}

			mfm.AssertExpectations(t)
		})
	}
}
