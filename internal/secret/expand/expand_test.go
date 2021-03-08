package expand_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/slok/agebox/internal/secret/expand"
	"github.com/stretchr/testify/assert"
)

func TestFSExpand(t *testing.T) {
	tests := map[string]struct {
		fs          func() fs.FS
		secretIDs   []string
		expExpanded []string
		expErr      bool
	}{
		"Not expanding anything should expand anything.": {
			fs: func() fs.FS {
				return fstest.MapFS{}
			},
			secretIDs:   []string{},
			expExpanded: []string{},
		},

		"Paths should be sanitized.": {
			fs: func() fs.FS {
				f := fstest.MapFS{}
				f["secret0"] = &fstest.MapFile{Data: []byte("data")}
				return f
			},
			secretIDs:   []string{"./secret0"},
			expExpanded: []string{"secret0"},
		},

		"Expanding files shouldn't expand anything.": {
			fs: func() fs.FS {
				f := fstest.MapFS{}
				f["secret0"] = &fstest.MapFile{Data: []byte("data")}
				f["secret2"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/secret1"] = &fstest.MapFile{Data: []byte("data")}
				return f
			},
			secretIDs:   []string{"secret0", "secret2"},
			expExpanded: []string{"secret0", "secret2"},
		},

		"Expanding files that don't exist should fail.": {
			fs: func() fs.FS {
				f := fstest.MapFS{}
				f["secret2"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/secret1"] = &fstest.MapFile{Data: []byte("data")}
				return f
			},
			secretIDs: []string{"secret0", "secret2"},
			expErr:    true,
		},

		"Expanding directories should expand at any level and return without directories.": {
			fs: func() fs.FS {
				f := fstest.MapFS{}
				f["secrets/secret0"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/secret1"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/sub-secrets/secret2"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/secret3"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/sub-secrets/secret4"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/sub-secrets/subsub-secrets/secret5"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/sub-secrets/subsub-secrets/secret6"] = &fstest.MapFile{Data: []byte("data")}
				return f
			},
			secretIDs: []string{"secrets"},
			expExpanded: []string{
				"secrets/secret0",
				"secrets/secret1",
				"secrets/secret3",
				"secrets/sub-secrets/secret2",
				"secrets/sub-secrets/secret4",
				"secrets/sub-secrets/subsub-secrets/secret5",
				"secrets/sub-secrets/subsub-secrets/secret6",
			},
		},

		"Expanding same file multiple times should return once.": {
			fs: func() fs.FS {
				f := fstest.MapFS{}
				f["secrets/secret0"] = &fstest.MapFile{Data: []byte("data")}
				return f
			},
			secretIDs: []string{"secrets/secret0", "secrets/secret0", "secrets/secret0"},
			expExpanded: []string{
				"secrets/secret0",
			},
		},

		"Expanding same directory multiple times should return once.": {
			fs: func() fs.FS {
				f := fstest.MapFS{}
				f["secrets/secret0"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/secret1"] = &fstest.MapFile{Data: []byte("data")}
				f["secrets/sub-secrets/secret2"] = &fstest.MapFile{Data: []byte("data")}
				return f
			},
			secretIDs: []string{"secrets/sub-secrets", "secrets"},
			expExpanded: []string{
				"secrets/sub-secrets/secret2",
				"secrets/secret0",
				"secrets/secret1",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			exp := expand.NewFSExpander(test.fs())
			gotExpanded, err := exp.Expand(context.TODO(), test.secretIDs)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expExpanded, gotExpanded)
			}
		})
	}
}
