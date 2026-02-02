package validate

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func Username(s string) error {
	if !usernameRe.MatchString(s) {
		return errors.New("invalid username")
	}
	return nil
}

func RootPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("root path is required")
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", errors.New("root path must be absolute")
	}
	// Reject volume root ("/", "C:\\", etc.).
	if filepath.Dir(clean) == clean {
		return "", errors.New("root path cannot be filesystem root")
	}
	// Avoid trailing separators for stable comparisons.
	clean = strings.TrimRight(clean, string(filepath.Separator))
	if clean == "" {
		return "", errors.New("invalid root path")
	}
	return clean, nil
}
