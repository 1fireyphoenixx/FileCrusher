// Package jailfs implements an afero.Fs confined to a root directory.
// All operations resolve paths through fsutil.ResolveWithinRoot.
package jailfs

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
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
		return nil, sanitizePathErr(err, filepath.Dir(name))
	}
	fh, err := f.osfs.Create(p)
	if err != nil {
		return nil, sanitizePathErr(err, name)
	}
	return fh, nil
}

// Mkdir creates a directory under the jailed root.
func (f *FS) Mkdir(name string, perm os.FileMode) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	if err := f.osfs.Mkdir(p, perm); err != nil {
		return sanitizePathErr(err, name)
	}
	return nil
}

// MkdirAll creates a directory tree under the jailed root.
func (f *FS) MkdirAll(path string, perm os.FileMode) error {
	p, err := f.local(path)
	if err != nil {
		return err
	}
	if err := f.osfs.MkdirAll(p, perm); err != nil {
		return sanitizePathErr(err, path)
	}
	return nil
}

// Open opens a file for reading under the jailed root.
func (f *FS) Open(name string) (afero.File, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	fh, err := f.osfs.Open(p)
	if err != nil {
		return nil, sanitizePathErr(err, name)
	}
	return fh, nil
}

// OpenFile opens a file with the given flags within the jailed root.
func (f *FS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	if flag&os.O_CREATE != 0 {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, sanitizePathErr(err, filepath.Dir(name))
		}
	}
	fh, err := f.osfs.OpenFile(p, flag, perm)
	if err != nil {
		return nil, sanitizePathErr(err, name)
	}
	return fh, nil
}

// Remove deletes a file under the jailed root.
func (f *FS) Remove(name string) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	if err := f.osfs.Remove(p); err != nil {
		return sanitizePathErr(err, name)
	}
	return nil
}

// RemoveAll recursively deletes a path under the jailed root.
func (f *FS) RemoveAll(path string) error {
	p, err := f.local(path)
	if err != nil {
		return err
	}
	if err := f.osfs.RemoveAll(p); err != nil {
		return sanitizePathErr(err, path)
	}
	return nil
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
		return sanitizePathErr(err, filepath.Dir(newname))
	}
	if err := f.osfs.Rename(oldp, newp); err != nil {
		return sanitizeLinkErr(err, oldname, newname)
	}
	return nil
}

// Stat returns file info for a path under the jailed root.
func (f *FS) Stat(name string) (os.FileInfo, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	info, err := f.osfs.Stat(p)
	if err != nil {
		return nil, sanitizePathErr(err, name)
	}
	return info, nil
}

// Name identifies this filesystem implementation.
func (f *FS) Name() string { return "jailfs" }

// Chmod changes permissions for a path under the jailed root.
func (f *FS) Chmod(name string, mode os.FileMode) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	if err := f.osfs.Chmod(p, mode); err != nil {
		return sanitizePathErr(err, name)
	}
	return nil
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
	if err := f.osfs.Chtimes(p, atime, mtime); err != nil {
		return sanitizePathErr(err, name)
	}
	return nil
}

// local resolves a user path to a safe local path under root.
func (f *FS) local(name string) (string, error) {
	return fsutil.ResolveWithinRoot(f.root, name)
}

func sanitizePathErr(err error, userPath string) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return &os.PathError{Op: pe.Op, Path: virtualPath(userPath), Err: pe.Err}
	}
	return err
}

func sanitizeLinkErr(err error, oldPath, newPath string) error {
	var le *os.LinkError
	if errors.As(err, &le) {
		return &os.LinkError{Op: le.Op, Old: virtualPath(oldPath), New: virtualPath(newPath), Err: le.Err}
	}
	return sanitizePathErr(err, oldPath)
}

func virtualPath(userPath string) string {
	normalized := strings.ReplaceAll(userPath, "\\", "/")
	normalized = strings.TrimLeft(normalized, "/")
	return path.Clean("/" + normalized)
}
