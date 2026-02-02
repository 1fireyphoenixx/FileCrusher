// Package webdavserver provides a WebDAV handler backed by FileCrusher users.
package webdavserver

import (
	"context"
	"os"
	"path/filepath"

	"filecrusher/internal/fsutil"
	"golang.org/x/net/webdav"
)

// JailFS adapts a jailed root path to webdav.FileSystem.
type JailFS struct {
	root string
}

// NewJailFS creates a WebDAV filesystem jailed to the given root.
func NewJailFS(root string) *JailFS {
	return &JailFS{root: filepath.Clean(root)}
}

// resolve maps a WebDAV path to a safe filesystem path.
func (fs *JailFS) resolve(name string) (string, error) {
	if fs.root == "" {
		return "", os.ErrInvalid
	}
	return fsutil.ResolveWithinRoot(fs.root, name)
}

// Mkdir creates a directory within the jailed root.
func (fs *JailFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	p, err := fs.resolve(name)
	if err != nil {
		return err
	}
	return os.Mkdir(p, perm)
}

// OpenFile opens a file with the given flags under the jailed root.
func (fs *JailFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	p, err := fs.resolve(name)
	if err != nil {
		return nil, err
	}
	if flag&os.O_CREATE != 0 {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(p, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// RemoveAll removes a path under the jailed root, but never the root itself.
func (fs *JailFS) RemoveAll(ctx context.Context, name string) error {
	p, err := fs.resolve(name)
	if err != nil {
		return err
	}
	// Safety: refuse to delete root
	if p == fs.root {
		return os.ErrPermission
	}
	return os.RemoveAll(p)
}

// Rename moves a path under the jailed root.
func (fs *JailFS) Rename(ctx context.Context, oldName, newName string) error {
	oldP, err := fs.resolve(oldName)
	if err != nil {
		return err
	}
	newP, err := fs.resolve(newName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newP), 0o700); err != nil {
		return err
	}
	return os.Rename(oldP, newP)
}

// Stat returns file info for a path under the jailed root.
func (fs *JailFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	p, err := fs.resolve(name)
	if err != nil {
		return nil, err
	}
	return os.Stat(p)
}

// Compile-time interface assertion.
var _ webdav.FileSystem = (*JailFS)(nil)
