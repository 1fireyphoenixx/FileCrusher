package jailfs

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"filecrusher/internal/fsutil"
	"github.com/spf13/afero"
)

type FS struct {
	root string
	osfs afero.Fs
}

func New(root string) *FS {
	return &FS{root: root, osfs: afero.NewOsFs()}
}

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

func (f *FS) Mkdir(name string, perm os.FileMode) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Mkdir(p, perm)
}

func (f *FS) MkdirAll(path string, perm os.FileMode) error {
	p, err := f.local(path)
	if err != nil {
		return err
	}
	return f.osfs.MkdirAll(p, perm)
}

func (f *FS) Open(name string) (afero.File, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	return f.osfs.Open(p)
}

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

func (f *FS) Remove(name string) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Remove(p)
}

func (f *FS) RemoveAll(path string) error {
	p, err := f.local(path)
	if err != nil {
		return err
	}
	return f.osfs.RemoveAll(p)
}

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

func (f *FS) Stat(name string) (os.FileInfo, error) {
	p, err := f.local(name)
	if err != nil {
		return nil, err
	}
	return f.osfs.Stat(p)
}

func (f *FS) Name() string { return "jailfs" }

func (f *FS) Chmod(name string, mode os.FileMode) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Chmod(p, mode)
}

func (f *FS) Chown(name string, uid, gid int) error {
	_ = name
	_ = uid
	_ = gid
	return errors.New("chown not supported")
}

func (f *FS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	p, err := f.local(name)
	if err != nil {
		return err
	}
	return f.osfs.Chtimes(p, atime, mtime)
}

func (f *FS) local(name string) (string, error) {
	return fsutil.ResolveWithinRoot(f.root, name)
}
