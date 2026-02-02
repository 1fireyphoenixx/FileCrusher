// Package sftpserver provides SSH-based SFTP and SCP services.
package sftpserver

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"filecrusher/internal/fsutil"
	"github.com/pkg/sftp"
)

// JailedHandlers implements sftp.Handlers with root path jail enforcement.
type JailedHandlers struct {
	Root string
}

// Fileread opens a file for reading within the jailed root.
func (h JailedHandlers) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	local, err := fsutil.ResolveWithinRoot(h.Root, r.Filepath)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(local)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Filewrite opens a file for writing within the jailed root.
func (h JailedHandlers) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	local, err := fsutil.ResolveWithinRoot(h.Root, r.Filepath)
	if err != nil {
		return nil, err
	}
	pf := r.Pflags()
	flags := 0
	if pf.Read && pf.Write {
		flags |= os.O_RDWR
	} else if pf.Write {
		flags |= os.O_WRONLY
	} else {
		flags |= os.O_RDONLY
	}
	if pf.Creat {
		flags |= os.O_CREATE
		if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
			return nil, err
		}
	}
	if pf.Trunc {
		flags |= os.O_TRUNC
	}
	if pf.Excl {
		flags |= os.O_EXCL
	}

	// Do NOT use O_APPEND with WriterAt.
	f, err := os.OpenFile(local, flags, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Filecmd handles filesystem mutations like rename, mkdir, and remove.
func (h JailedHandlers) Filecmd(r *sftp.Request) error {
	local, err := fsutil.ResolveWithinRoot(h.Root, r.Filepath)
	if err != nil {
		return err
	}

	switch r.Method {
	case "Setstat":
		attrs := r.Attributes()
		flags := r.AttrFlags()
		if flags.Permissions {
			if err := os.Chmod(local, attrs.FileMode()); err != nil {
				return err
			}
		}
		if flags.Acmodtime {
			if err := os.Chtimes(local, attrs.AccessTime(), attrs.ModTime()); err != nil {
				return err
			}
		}
		if flags.UidGid {
			return errors.New("chown not supported")
		}
		return nil
	case "Rename":
		target, err := fsutil.ResolveWithinRoot(h.Root, r.Target)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.Rename(local, target)
	case "Rmdir":
		return os.Remove(local)
	case "Mkdir":
		return os.MkdirAll(local, 0o700)
	case "Remove":
		return os.Remove(local)
	case "Link", "Symlink":
		return errors.New("links not supported")
	default:
		return errors.New("unsupported command")
	}
}

// Filelist lists directories or stats files within the jailed root.
func (h JailedHandlers) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	local, err := fsutil.ResolveWithinRoot(h.Root, r.Filepath)
	if err != nil {
		return nil, err
	}

	switch r.Method {
	case "List":
		ents, err := os.ReadDir(local)
		if err != nil {
			return nil, err
		}
		infos := make([]os.FileInfo, 0, len(ents))
		for _, e := range ents {
			fi, err := e.Info()
			if err != nil {
				continue
			}
			infos = append(infos, fi)
		}
		return staticLister(infos), nil
	case "Stat":
		fi, err := os.Stat(local)
		if err != nil {
			return nil, err
		}
		return staticLister([]os.FileInfo{fi}), nil
	case "Readlink":
		return nil, errors.New("readlink not supported")
	default:
		return nil, errors.New("unsupported list")
	}
}

// staticLister wraps a fixed slice of FileInfo for listing.
type staticLister []os.FileInfo

// ListAt satisfies sftp.ListerAt with slice-based pagination.
func (l staticLister) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset < 0 {
		return 0, io.EOF
	}
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if int64(n)+offset >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}
