// Package jailfs implements an afero.Fs confined to a root directory.
// All operations resolve paths through fsutil.ResolveWithinRoot.
package jailfs

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"filecrusher/internal/fsutil"
	"github.com/spf13/afero"
)

// FS is an afero filesystem that rejects path traversal outside its root.
type FS struct {
	root string
	osfs afero.Fs
}

// New returns a jailed filesystem rooted at the provided directory.
func New(root string) *FS {
	return &FS{root: root, osfs: afero.NewOsFs()}
}

// Create opens a file for writing under the jailed root.
func (f *FS) Create(name string) (afero.File, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	return f.osfs.Create(p)
}

// Mkdir creates a directory under the jailed root.
func (f *FS) Mkdir(name string, perm os.FileMode) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Mkdir(p, perm)
}

// MkdirAll creates a directory tree under the jailed root.
func (f *FS) MkdirAll(path string, perm os.FileMode) error {
	p, err := f.local(path)
	if err != nil {
		return err
	}
	return f.osfs.MkdirAll(p, perm)
}

// Open opens a file for reading under the jailed root.
func (f *FS) Open(name string) (afero.File, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	return f.osfs.Open(p)
}

// OpenFile opens a file with the given flags within the jailed root.
func (f *FS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	if flag&os.O_CREATE != 0 {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, err
		}
	}
	return f.osfs.OpenFile(p, flag, perm)
}

// Remove deletes a file under the jailed root.
func (f *FS) Remove(name string) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Remove(p)
}

// RemoveAll recursively deletes a path under the jailed root.
func (f *FS) RemoveAll(path string) error {
	p, err := f.local(path)
	if err != nil {
		return err
	}
	return f.osfs.RemoveAll(p)
}

// Rename moves a path within the jailed root.
func (f *FS) Rename(oldname, newname string) error {
	oldp, err := f.local(oldname)
	if err != nil {
		return err
	}
	newp, err := f.local(newname)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newp), 0o700); err != nil {
		return err
	}
	return f.osfs.Rename(oldp, newp)
}

// Stat returns file info for a path under the jailed root.
func (f *FS) Stat(name string) (os.FileInfo, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	return f.osfs.Stat(p)
}

// Name identifies this filesystem implementation.
func (f *FS) Name() string { return "jailfs" }

// Chmod changes permissions for a path under the jailed root.
func (f *FS) Chmod(name string, mode os.FileMode) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Chmod(p, mode)
}

// Chown is not supported for this filesystem implementation.
func (f *FS) Chown(name string, uid, gid int) error {
	_ = name
	_ = uid
	_ = gid
	return errors.New("chown not supported")
}

// Chtimes updates file timestamps under the jailed root.
func (f *FS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Chtimes(p, atime, mtime)
}

// local resolves a user path to a safe local path under root.
func (f *FS) local(name string) (string, error) {
	return fsutil.ResolveWithinRoot(f.root, name)
}
