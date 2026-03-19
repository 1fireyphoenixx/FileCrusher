package ftpserver

import (
	"errors"
	"os"
	"testing"

	"filecrusher/internal/jailfs"
	ftp "github.com/fclairamb/ftpserverlib"
)

func TestQuotaFSRejectsOverLimitWrite(t *testing.T) {
	root := t.TempDir()
	fs := newQuotaFS(jailfs.New(root), root, 5)

	fh, err := fs.OpenFile("/upload.bin", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { _ = fh.Close() })

	if _, err := fh.Write([]byte("hello")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := fh.Write([]byte("x")); !errors.Is(err, ftp.ErrStorageExceeded) {
		t.Fatalf("expected ErrStorageExceeded, got %v", err)
	}
}
