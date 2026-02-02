// Package fsutil provides filesystem safety helpers.
// It focuses on preventing path traversal in user-supplied paths.
package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrPathTraversal indicates a path resolved outside the allowed root.
var ErrPathTraversal = errors.New("path escapes root")

// ResolveWithinRoot maps a user-provided path to a local filesystem path under root.
// It rejects any traversal outside root, including via existing symlinks.
// ResolveWithinRoot maps a user path to a local path inside root.
// It rejects absolute traversal and symlink escapes.
func ResolveWithinRoot(root, userPath string) (string, error) {
	if root == "" {
		return "", errors.New("root is required")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootAbs = filepath.Clean(rootAbs)

	// Force relative paths.
	p := strings.TrimLeft(userPath, "/\\")
	localRel := filepath.FromSlash(p)
	joined := filepath.Join(rootAbs, localRel)
	joined = filepath.Clean(joined)

	if !isWithin(rootAbs, joined) {
		return "", ErrPathTraversal
	}

	// Deny symlink traversal: if any existing component under root is a symlink, reject.
	if hasSymlinkComponent(rootAbs, joined) {
		return "", ErrPathTraversal
	}

	// If any existing segment is a symlink to outside root, block it.
	existing := nearestExisting(joined)
	if existing != "" {
		resolved, err := filepath.EvalSymlinks(existing)
		if err != nil {
			return "", err
		}
		resolved = filepath.Clean(resolved)
		if !isWithin(rootAbs, resolved) {
			return "", ErrPathTraversal
		}
	}

	return joined, nil
}

// hasSymlinkComponent checks for symlinks along the path under root.
// Any symlink is treated as unsafe for traversal.
func hasSymlinkComponent(rootAbs, fullPath string) bool {
	rootAbs = filepath.Clean(rootAbs)
	fullPath = filepath.Clean(fullPath)
	if !isWithin(rootAbs, fullPath) {
		return true
	}
	rel, err := filepath.Rel(rootAbs, fullPath)
	if err != nil {
		return true
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return false
	}
	cur := rootAbs
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		cur = filepath.Join(cur, p)
		st, err := os.Lstat(cur)
		if err != nil {
			// Component doesn't exist (yet): no symlink to traverse.
			return false
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// isWithin reports whether candidate is equal to or nested under root.
func isWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if root == candidate {
		return true
	}
	sep := string(filepath.Separator)
	if !strings.HasSuffix(root, sep) {
		root += sep
	}
	return strings.HasPrefix(candidate, root)
}

// nearestExisting walks up from p to find the nearest existing path.
// It returns an empty string for errors or if nothing exists.
func nearestExisting(p string) string {
	cur := p
	for {
		_, err := os.Lstat(cur)
		if err == nil {
			return cur
		}
		if !os.IsNotExist(err) {
			return ""
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}
