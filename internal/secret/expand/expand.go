package expand

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
)

// Expander knows how to expand multiple secretIDs.
type Expander interface {
	Expand(ctx context.Context, secretIDs []string) ([]string, error)
}

type fsExpander struct {
	fs fs.FS
}

// NewFSExpander returns a new FS expander.
func NewFSExpander(fs fs.FS) Expander {
	return fsExpander{fs: fs}
}

func (f fsExpander) Expand(ctx context.Context, secretIDs []string) ([]string, error) {
	visited := map[string]struct{}{}
	expanded := []string{}
	for _, secret := range secretIDs {
		_, ok := visited[secret]
		if ok {
			continue
		}

		exp, err := f.expandSecret(ctx, visited, secret)
		if err != nil {
			return nil, fmt.Errorf("could not expand %q: %w", secret, err)
		}

		expanded = append(expanded, exp...)
	}

	return expanded, nil
}

func (f fsExpander) expandSecret(ctx context.Context, visited map[string]struct{}, secretID string) ([]string, error) {
	secretID = filepath.Clean(secretID)
	expanded := []string{}

	err := fs.WalkDir(f.fs, secretID, fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
		defer func() {
			visited[path] = struct{}{}
		}()

		if err != nil {
			return err
		}

		if !d.IsDir() {
			expanded = append(expanded, path)
		}

		// If is a directory and already visited then skip dir expansion.
		_, ok := visited[path]
		if ok {
			return fs.SkipDir
		}

		return nil
	}))
	if err != nil {
		return nil, err
	}

	return expanded, nil
}
