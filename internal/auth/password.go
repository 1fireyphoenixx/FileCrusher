// Package auth provides password hashing and token utilities.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params describes Argon2id hashing parameters.
// These values are embedded in the PHC hash string.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2Params returns tuned defaults for interactive logins.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltLen:     16,
		KeyLen:      32,
	}
}

// HashPassword returns a PHC-style Argon2id string.
// Format: argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>
func HashPassword(password string, p Argon2Params) (string, error) {
	if password == "" {
		return "", errors.New("password is required")
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf(
		"argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory,
		p.Iterations,
		p.Parallelism,
		enc.EncodeToString(salt),
		enc.EncodeToString(h),
	), nil
}

// dummyHash is a pre-computed argon2id hash (of "x") using DefaultArgon2Params.
// Used to burn CPU time when a user is not found, preventing timing side-channels.
var dummyHash = mustDummyHash()

func mustDummyHash() string {
	h, err := HashPassword("x", DefaultArgon2Params())
	if err != nil {
		panic("auth: failed to generate dummy hash: " + err.Error())
	}
	return h
}

// DummyVerify performs a password hash against a dummy value.
// Call this when the target user does not exist so the response
// takes the same time as a real password check.
func DummyVerify(password string) {
	_, _ = VerifyPassword(password, dummyHash)
}

// VerifyPassword checks a plaintext password against a PHC-encoded hash.
func VerifyPassword(password, encoded string) (bool, error) {
	if password == "" || encoded == "" {
		return false, nil
	}
	p, salt, want, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) == 1 {
		return true, nil
	}
	return false, nil
}

// parsePHC parses an Argon2id PHC string into params, salt, and hash.
func parsePHC(s string) (Argon2Params, []byte, []byte, error) {
	// argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	parts := strings.Split(s, "$")
	if len(parts) != 5 {
		return Argon2Params{}, nil, nil, errors.New("invalid password hash format")
	}
	if parts[0] != "argon2id" {
		return Argon2Params{}, nil, nil, errors.New("unsupported password hash algorithm")
	}
	if !strings.HasPrefix(parts[1], "v=") {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2 version")
	}
	ver, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v="))
	if err != nil || ver != argon2.Version {
		return Argon2Params{}, nil, nil, errors.New("unsupported argon2 version")
	}

	var p Argon2Params
	params := strings.Split(parts[2], ",")
	for _, kv := range params {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) != 2 {
			return Argon2Params{}, nil, nil, errors.New("invalid argon2 parameters")
		}
		switch pair[0] {
		case "m":
			v, err := strconv.ParseUint(pair[1], 10, 32)
			if err != nil {
				return Argon2Params{}, nil, nil, errors.New("invalid argon2 memory")
			}
			p.Memory = uint32(v)
		case "t":
			v, err := strconv.ParseUint(pair[1], 10, 32)
			if err != nil {
				return Argon2Params{}, nil, nil, errors.New("invalid argon2 iterations")
			}
			p.Iterations = uint32(v)
		case "p":
			v, err := strconv.ParseUint(pair[1], 10, 8)
			if err != nil {
				return Argon2Params{}, nil, nil, errors.New("invalid argon2 parallelism")
			}
			p.Parallelism = uint8(v)
		default:
			return Argon2Params{}, nil, nil, errors.New("unknown argon2 parameter")
		}
	}

	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2 salt")
	}
	hash, err := enc.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2 hash")
	}
	if len(hash) < 16 {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2 hash length")
	}
	return p, salt, hash, nil
}
