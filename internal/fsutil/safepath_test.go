// Package fsutil tests validate path traversal protections.
package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestResolveWithinRootRejectsTraversal blocks obvious .. escapes.
func TestResolveWithinRootRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := ResolveWithinRoot(root, "../etc/passwd"); err == nil {
		t.Fatalf("expected traversal to be rejected")
	}
	if _, err := ResolveWithinRoot(root, "/../etc/passwd"); err == nil {
		t.Fatalf("expected traversal to be rejected")
	}
}

// TestResolveWithinRootRejectsSymlinkEscape blocks symlink-based escapes.
func TestResolveWithinRootRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Symlink creation may require privileges.
		t.Skip("symlink behavior varies on windows")
	}
	root := t.TempDir()
	outside := t.TempDir()

	// root/link -> outside
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	if _, err := ResolveWithinRoot(root, "link/escape.txt"); err == nil {
		t.Fatalf("expected symlink escape to be rejected")
	}
}
