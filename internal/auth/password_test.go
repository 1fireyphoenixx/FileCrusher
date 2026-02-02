// Package auth tests cover password hashing/verification.
package auth

import "testing"

// TestHashAndVerifyPassword validates positive and negative password checks.
func TestHashAndVerifyPassword(t *testing.T) {
	h, err := HashPassword("secret", DefaultArgon2Params())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword("secret", h)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatalf("expected password to verify")
	}

	ok, err = VerifyPassword("wrong", h)
	if err != nil {
		t.Fatalf("VerifyPassword(wrong): %v", err)
	}
	if ok {
		t.Fatalf("expected wrong password to fail")
	}
}
