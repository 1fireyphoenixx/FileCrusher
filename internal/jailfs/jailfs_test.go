package jailfs

import (
	"strings"
	"testing"
)

func TestOpenErrorDoesNotLeakRootPath(t *testing.T) {
	root := t.TempDir()
	fs := New(root)

	_, err := fs.Open("doesnotexist.txt")
	if err == nil {
		t.Fatalf("expected open error")
	}

	errText := err.Error()
	if strings.Contains(errText, root) {
		t.Fatalf("error leaked root path: %q", errText)
	}
	if !strings.Contains(errText, "/doesnotexist.txt") {
		t.Fatalf("error does not contain virtual path: %q", errText)
	}
}

func TestStatErrorDoesNotLeakRootPath(t *testing.T) {
	root := t.TempDir()
	fs := New(root)

	_, err := fs.Stat("missing.bin")
	if err == nil {
		t.Fatalf("expected stat error")
	}

	errText := err.Error()
	if strings.Contains(errText, root) {
		t.Fatalf("error leaked root path: %q", errText)
	}
	if !strings.Contains(errText, "/missing.bin") {
		t.Fatalf("error does not contain virtual path: %q", errText)
	}
}

func TestRenameErrorDoesNotLeakRootPath(t *testing.T) {
	root := t.TempDir()
	fs := New(root)

	err := fs.Rename("from-missing.txt", "to.txt")
	if err == nil {
		t.Fatalf("expected rename error")
	}

	errText := err.Error()
	if strings.Contains(errText, root) {
		t.Fatalf("error leaked root path: %q", errText)
	}
	if !strings.Contains(errText, "/from-missing.txt") {
		t.Fatalf("error does not contain old virtual path: %q", errText)
	}
	if !strings.Contains(errText, "/to.txt") {
		t.Fatalf("error does not contain new virtual path: %q", errText)
	}
}
