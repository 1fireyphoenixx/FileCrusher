package sftpserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeSFTPErrorPathErrorStripsRootPrefix(t *testing.T) {
	root := filepath.Join(string(os.PathSeparator), "storage", "pentest", "alice")
	err := &os.PathError{Op: "open", Path: filepath.Join(root, "docs", "secret.txt"), Err: os.ErrNotExist}

	sanitized := sanitizeSFTPError(root, err)

	var got *os.PathError
	if !errors.As(sanitized, &got) {
		t.Fatalf("expected *os.PathError, got %T", sanitized)
	}
	if got.Path != "/docs/secret.txt" {
		t.Fatalf("expected redacted relative path, got %q", got.Path)
	}
	if errors.Is(sanitized, os.ErrNotExist) == false {
		t.Fatalf("expected sanitized error to preserve unwrap semantics")
	}
	if strings.Contains(got.Error(), root) {
		t.Fatalf("sanitized error still contains absolute root: %q", got.Error())
	}
}

func TestSanitizeSFTPErrorLinkErrorStripsRootPrefix(t *testing.T) {
	root := filepath.Join(string(os.PathSeparator), "storage", "pentest", "bob")
	err := &os.LinkError{
		Op:  "rename",
		Old: filepath.Join(root, "old.txt"),
		New: filepath.Join(root, "nested", "new.txt"),
		Err: os.ErrPermission,
	}

	sanitized := sanitizeSFTPError(root, err)

	var got *os.LinkError
	if !errors.As(sanitized, &got) {
		t.Fatalf("expected *os.LinkError, got %T", sanitized)
	}
	if got.Old != "/old.txt" {
		t.Fatalf("expected redacted old path, got %q", got.Old)
	}
	if got.New != "/nested/new.txt" {
		t.Fatalf("expected redacted new path, got %q", got.New)
	}
	if strings.Contains(got.Error(), root) {
		t.Fatalf("sanitized error still contains absolute root: %q", got.Error())
	}
}

func TestStripInternalRootPrefixLeavesUnrelatedPath(t *testing.T) {
	root := filepath.Join(string(os.PathSeparator), "storage", "pentest", "carol")
	otherPath := filepath.Join(string(os.PathSeparator), "tmp", "file.txt")

	if got := stripInternalRootPrefix(otherPath, root); got != filepath.Clean(otherPath) {
		t.Fatalf("expected unrelated path unchanged, got %q", got)
	}
}
