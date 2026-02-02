// Package auth provides password hashing and token utilities.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// NewToken returns a URL-safe random token with at least 16 bytes of entropy.
func NewToken(nbytes int) (string, error) {
	if nbytes < 16 {
		return "", errors.New("token size too small")
	}
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
