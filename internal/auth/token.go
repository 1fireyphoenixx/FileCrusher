package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

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
