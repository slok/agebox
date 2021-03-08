package fs_test

import (
	"context"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/slok/agebox/internal/key/keymock"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/storage"
	storagefs "github.com/slok/agebox/internal/storage/fs"
)

type testKey string

func (t testKey) Data() []byte { return []byte(t) }
func (t testKey) IsPublic()    {}
func (t testKey) IsPrivate()   {}

func TestGetPrivateKey(t *testing.T) {
	tests := map[string]struct {
		config storagefs.KeyRepositoryConfig
		mock   func(f fstest.MapFS, m *keymock.Factory)
		expKey model.PrivateKey
		expErr bool
	}{
		"Missing private key should fail.": {
			config: storagefs.KeyRepositoryConfig{
				PrivateKeyPath: "test/key1",
			},
			mock:   func(f fstest.MapFS, m *keymock.Factory) {},
			expErr: true,
		},

		"Loading an existing key should load the key.": {
			config: storagefs.KeyRepositoryConfig{
				PrivateKeyPath: "test/key1",
			},
			mock: func(f fstest.MapFS, m *keymock.Factory) {
				f["test/key1"] = &fstest.MapFile{Data: []byte("key1data")}
				m.On("GetPrivateKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)
			},
			expKey: testKey("key1"),
		},

		"Loading an existing key error should fail.": {
			config: storagefs.KeyRepositoryConfig{
				PrivateKeyPath: "test/key1",
			},
			mock: func(f fstest.MapFS, m *keymock.Factory) {
				f["test/key1"] = &fstest.MapFile{Data: []byte("key1data")}
				m.On("GetPrivateKey", mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks.
			mkf := &keymock.Factory{}
			mfs := fstest.MapFS{}
			test.mock(mfs, mkf)

			test.config.FS = mfs
			test.config.KeyFactory = mkf
			repo, _ := storagefs.NewKeyRepository(test.config)

			gotKey, err := repo.GetPrivateKey(context.TODO())

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expKey, gotKey)
			}
			mkf.AssertExpectations(t)
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	tests := map[string]struct {
		config     storagefs.KeyRepositoryConfig
		mock       func(f fstest.MapFS, m *keymock.Factory)
		expKeyList storage.PublicKeyList
		expErr     bool
	}{
		"Not having any public key should not fail.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(f fstest.MapFS, m *keymock.Factory) {
				f["test/keys"] = &fstest.MapFile{Mode: fs.ModeDir}
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{}},
		},

		"Having a single key at root should load the key.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(f fstest.MapFS, m *keymock.Factory) {
				f["test/keys/key1.pub"] = &fstest.MapFile{Data: []byte("key1data")}
				m.On("GetPublicKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{
				testKey("key1"),
			}},
		},

		"Having an error while loading a key should fail.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(f fstest.MapFS, m *keymock.Factory) {
				f["test/keys/key1.pub"] = &fstest.MapFile{Data: []byte("key1data")}
				m.On("GetPublicKey", mock.Anything, mock.Anything).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having a multiple keys at different levels should load the keys.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(f fstest.MapFS, m *keymock.Factory) {
				f["test/keys/key1.pub"] = &fstest.MapFile{Data: []byte("key1data")}
				f["test/keys/keys-a/key2.pub"] = &fstest.MapFile{Data: []byte("key2data")}
				f["test/keys/keys-a/keys-b/key3.pub"] = &fstest.MapFile{Data: []byte("key3data")}
				f["test/keys/keys-a/keys-c/key4.pub"] = &fstest.MapFile{Data: []byte("key4data")}
				f["test/keys/keys-a/keys-c/key5.pub"] = &fstest.MapFile{Data: []byte("key5data")}
				m.On("GetPublicKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)
				m.On("GetPublicKey", mock.Anything, []byte("key2data")).Once().Return(testKey("key2"), nil)
				m.On("GetPublicKey", mock.Anything, []byte("key3data")).Once().Return(testKey("key3"), nil)
				m.On("GetPublicKey", mock.Anything, []byte("key4data")).Once().Return(testKey("key4"), nil)
				m.On("GetPublicKey", mock.Anything, []byte("key5data")).Once().Return(testKey("key5"), nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{
				testKey("key1"),
				testKey("key2"),
				testKey("key3"),
				testKey("key4"),
				testKey("key5"),
			}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks.
			mkf := &keymock.Factory{}
			mfs := fstest.MapFS{}
			test.mock(mfs, mkf)

			test.config.FS = mfs
			test.config.KeyFactory = mkf
			repo, _ := storagefs.NewKeyRepository(test.config)

			gotKeyList, err := repo.ListPublicKeys(context.TODO())

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expKeyList, *gotKeyList)
			}
			mkf.AssertExpectations(t)
		})
	}

}
