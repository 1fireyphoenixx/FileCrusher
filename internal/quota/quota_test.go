package quota

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryUsage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.bin"), make([]byte, 3), 0o600); err != nil {
		t.Fatalf("write a.bin: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.bin"), make([]byte, 5), 0o600); err != nil {
		t.Fatalf("write b.bin: %v", err)
	}
	got, err := DirectoryUsage(root)
	if err != nil {
		t.Fatalf("DirectoryUsage: %v", err)
	}
	if got != 8 {
		t.Fatalf("usage got %d want 8", got)
	}
}

func TestMaxFileSize(t *testing.T) {
	root := t.TempDir()
	keep := filepath.Join(root, "keep.bin")
	target := filepath.Join(root, "target.bin")
	if err := os.WriteFile(keep, make([]byte, 4), 0o600); err != nil {
		t.Fatalf("write keep: %v", err)
	}
	if err := os.WriteFile(target, make([]byte, 3), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	maxFile, existing, err := MaxFileSize(root, target, 10)
	if err != nil {
		t.Fatalf("MaxFileSize: %v", err)
	}
	if existing != 3 {
		t.Fatalf("existing got %d want 3", existing)
	}
	if maxFile != 6 {
		t.Fatalf("max file got %d want 6", maxFile)
	}
}
