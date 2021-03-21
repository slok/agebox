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
	"github.com/slok/agebox/internal/storage/fs/fsmock"
)

type testFile struct {
	name string
	f    *fstest.MapFile
}

func (t testFile) Name() string               { return t.name }
func (t testFile) Type() fs.FileMode          { return t.f.Mode.Type() }
func (t testFile) IsDir() bool                { return t.f.Mode&fs.ModeDir != 0 }
func (t testFile) Info() (fs.FileInfo, error) { return nil, nil }

type testKey string

func (t testKey) Data() []byte { return []byte(t) }
func (t testKey) IsPublic()    {}
func (t testKey) IsPrivate()   {}

func TestGetPrivateKey(t *testing.T) {
	tests := map[string]struct {
		config storagefs.KeyRepositoryConfig
		mock   func(mr *fsmock.FileManager, mf *keymock.Factory)
		expKey model.PrivateKey
		expErr bool
	}{
		"Missing private key should fail.": {
			config: storagefs.KeyRepositoryConfig{
				PrivateKeyPath: "test/key1",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("ReadFile", mock.Anything, "test/key1").Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Loading an existing key should load the key.": {
			config: storagefs.KeyRepositoryConfig{
				PrivateKeyPath: "test/key1",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("ReadFile", mock.Anything, "test/key1").Once().Return([]byte("key1data"), nil)
				mf.On("GetPrivateKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)
			},
			expKey: testKey("key1"),
		},

		"Loading an existing key error should fail.": {
			config: storagefs.KeyRepositoryConfig{
				PrivateKeyPath: "test/key1",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("ReadFile", mock.Anything, "test/key1").Once().Return([]byte("key1data"), nil)
				mf.On("GetPrivateKey", mock.Anything, []byte("key1data")).Once().Return(nil, fmt.Errorf("something"))
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks.
			mkf := &keymock.Factory{}
			mfs := &fsmock.FileManager{}
			test.mock(mfs, mkf)

			test.config.FileManager = mfs
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
		mock       func(mr *fsmock.FileManager, mf *keymock.Factory)
		expKeyList storage.PublicKeyList
		expErr     bool
	}{
		"Not having any public key should not fail.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("WalkDir", mock.Anything, "test/keys", mock.Anything).Once().Return(nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{}},
		},

		"Having a single key at root should load the key.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("WalkDir", mock.Anything, "test/keys", mock.Anything).Once().Return(nil).Run(func(args mock.Arguments) {
					fn := args.Get(2).(fs.WalkDirFunc)

					// Mock 1 public key.
					_ = fn("test/keys/key1.pub", testFile{
						name: "test/keys/key1.pub",
						f:    &fstest.MapFile{Data: []byte("key1data")},
					}, nil)
				})

				mr.On("ReadFile", mock.Anything, "test/keys/key1.pub").Once().Return([]byte("key1data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{
				testKey("key1"),
			}},
		},

		"Having a multiple keys in the same file should load all the keys.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("WalkDir", mock.Anything, "test/keys", mock.Anything).Once().Return(nil).Run(func(args mock.Arguments) {
					fn := args.Get(2).(fs.WalkDirFunc)

					// Mock 1 public key.
					_ = fn("test/keys/multikey.pub", testFile{
						name: "test/keys/multikey.pub",
						f:    &fstest.MapFile{Data: []byte("key1data")},
					}, nil)
				})

				mr.On("ReadFile", mock.Anything, "test/keys/multikey.pub").Once().Return([]byte("key1data\nkey2data\n  \n# nokeydata \nkey3data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key2data")).Once().Return(testKey("key2"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key3data")).Once().Return(testKey("key3"), nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{
				testKey("key1"),
				testKey("key2"),
				testKey("key3"),
			}},
		},

		"Having valid and invalid keys, should ignore the invalid ones.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("WalkDir", mock.Anything, "test/keys", mock.Anything).Once().Return(nil).Run(func(args mock.Arguments) {
					fn := args.Get(2).(fs.WalkDirFunc)

					// Mock 3 public key.
					_ = fn("test/keys/key1.pub", testFile{
						name: "test/keys/key1.pub",
						f:    &fstest.MapFile{Data: []byte("key1data")},
					}, nil)

					_ = fn("test/keys/key2.pub", testFile{
						name: "test/keys/key2.pub",
						f:    &fstest.MapFile{Data: []byte("key2data")},
					}, nil)

					_ = fn("test/keys/key3.pub", testFile{
						name: "test/keys/key3.pub",
						f:    &fstest.MapFile{Data: []byte("key3data")},
					}, nil)
				})

				mr.On("ReadFile", mock.Anything, "test/keys/key1.pub").Once().Return([]byte("key1data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)

				// Invalid key.
				mr.On("ReadFile", mock.Anything, "test/keys/key2.pub").Once().Return([]byte("key2data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key2data")).Once().Return(nil, fmt.Errorf("something"))

				mr.On("ReadFile", mock.Anything, "test/keys/key3.pub").Once().Return([]byte("key3data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key3data")).Once().Return(testKey("key3"), nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{
				testKey("key1"),
				testKey("key3"),
			}},
		},

		"Having an error while loading a key should fail.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("WalkDir", mock.Anything, "test/keys", mock.Anything).Once().Return(fmt.Errorf("something"))
			},
			expErr: true,
		},

		"Having multiple keys at root should load the keys.": {
			config: storagefs.KeyRepositoryConfig{
				PublicKeysPath: "test/keys",
			},
			mock: func(mr *fsmock.FileManager, mf *keymock.Factory) {
				mr.On("WalkDir", mock.Anything, "test/keys", mock.Anything).Once().Return(nil).Run(func(args mock.Arguments) {
					fn := args.Get(2).(fs.WalkDirFunc)

					// Mock 2 public key.
					_ = fn("test/keys/key1.pub", testFile{
						name: "test/keys/key1.pub",
						f:    &fstest.MapFile{Data: []byte("key1data")},
					}, nil)

					_ = fn("test/keys/key2.pub", testFile{
						name: "test/keys/key2.pub",
						f:    &fstest.MapFile{Data: []byte("key2data")},
					}, nil)
				})

				mr.On("ReadFile", mock.Anything, "test/keys/key1.pub").Once().Return([]byte("key1data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key1data")).Once().Return(testKey("key1"), nil)

				mr.On("ReadFile", mock.Anything, "test/keys/key2.pub").Once().Return([]byte("key2data"), nil)
				mf.On("GetPublicKey", mock.Anything, []byte("key2data")).Once().Return(testKey("key2"), nil)
			},
			expKeyList: storage.PublicKeyList{Items: []model.PublicKey{
				testKey("key1"),
				testKey("key2"),
			}},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks.
			mkf := &keymock.Factory{}
			mfs := &fsmock.FileManager{}
			test.mock(mfs, mkf)

			test.config.FileManager = mfs
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
