package sftpserver

import (
	"errors"
	"os"
	"testing"
)

func TestQuotaWriterAtRejectsOverflow(t *testing.T) {
	path := t.TempDir() + "/f.bin"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	w := &quotaWriterAt{f: f, maxFileSize: 4}
	if _, err := w.WriteAt([]byte("test"), 0); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := w.WriteAt([]byte("x"), 4); !errors.Is(err, errQuotaExceeded) {
		t.Fatalf("expected errQuotaExceeded, got %v", err)
	}
}
