package ftpserver

import (
	"io"
	"os"
	"sync"
	"time"

	"filecrusher/internal/fsutil"
	"filecrusher/internal/quota"
	ftp "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

type quotaFS struct {
	base       afero.Fs
	root       string
	quotaBytes int64
}

func newQuotaFS(base afero.Fs, root string, quotaBytes int64) *quotaFS {
	return &quotaFS{base: base, root: root, quotaBytes: quotaBytes}
}

func (f *quotaFS) Create(name string) (afero.File, error) {
	return f.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (f *quotaFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	fh, err := f.base.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	if f.quotaBytes <= 0 || !isWriteFlag(flag) {
		return fh, nil
	}
	local, err := fsutil.ResolveWithinRoot(f.root, name)
	if err != nil {
		_ = fh.Close()
		return nil, err
	}
	maxFileSize, existingSize, err := quota.MaxFileSize(f.root, local, f.quotaBytes)
	if err != nil {
		_ = fh.Close()
		return nil, err
	}
	initialSize := existingSize
	if flag&os.O_TRUNC != 0 {
		initialSize = 0
	}
	return &quotaFile{
		File:        fh,
		maxFileSize: maxFileSize,
		position:    startPosition(fh),
		appendMode:  flag&os.O_APPEND != 0,
		initialSize: initialSize,
	}, nil
}

func (f *quotaFS) Name() string                                 { return f.base.Name() }
func (f *quotaFS) Open(name string) (afero.File, error)         { return f.base.Open(name) }
func (f *quotaFS) Mkdir(name string, perm os.FileMode) error    { return f.base.Mkdir(name, perm) }
func (f *quotaFS) MkdirAll(path string, perm os.FileMode) error { return f.base.MkdirAll(path, perm) }
func (f *quotaFS) Remove(name string) error                     { return f.base.Remove(name) }
func (f *quotaFS) RemoveAll(path string) error                  { return f.base.RemoveAll(path) }
func (f *quotaFS) Rename(oldname, newname string) error         { return f.base.Rename(oldname, newname) }
func (f *quotaFS) Stat(name string) (os.FileInfo, error)        { return f.base.Stat(name) }
func (f *quotaFS) Chmod(name string, mode os.FileMode) error    { return f.base.Chmod(name, mode) }
func (f *quotaFS) Chown(name string, uid, gid int) error        { return f.base.Chown(name, uid, gid) }
func (f *quotaFS) Chtimes(name string, atime, mtime time.Time) error {
	return f.base.Chtimes(name, atime, mtime)
}

func isWriteFlag(flag int) bool {
	return flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_TRUNC|os.O_CREATE) != 0
}

type quotaFile struct {
	afero.File
	maxFileSize int64
	initialSize int64
	appendMode  bool
	position    int64
	mu          sync.Mutex
}

func (f *quotaFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.allowWrite(int64(len(p)), f.position) {
		return 0, ftp.ErrStorageExceeded
	}
	n, err := f.File.Write(p)
	f.position += int64(n)
	return n, err
}

func (f *quotaFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.allowWrite(int64(len(p)), off) {
		return 0, ftp.ErrStorageExceeded
	}
	return f.File.WriteAt(p, off)
}

func (f *quotaFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pos, err := f.File.Seek(offset, whence)
	if err == nil {
		f.position = pos
	}
	return pos, err
}

func (f *quotaFile) allowWrite(n, at int64) bool {
	if f.appendMode {
		st, err := f.File.Stat()
		if err == nil {
			at = st.Size()
		}
	}
	end := at + n
	if end < 0 {
		return false
	}
	if end <= f.initialSize {
		return true
	}
	return end <= f.maxFileSize
}

func startPosition(f afero.File) int64 {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0
	}
	return pos
}
