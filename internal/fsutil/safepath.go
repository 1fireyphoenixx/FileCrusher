package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrPathTraversal = errors.New("path escapes root")

// ResolveWithinRoot maps a user-provided path to a local filesystem path under root.
// It rejects any traversal outside root, including via existing symlinks.
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
