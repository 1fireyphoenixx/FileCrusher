package sftpserver

import (
	"errors"
	"testing"
	"time"
)

func TestRejectAuthEnforcesMinimumDelay(t *testing.T) {
	start := time.Now()
	_, err := rejectAuth(start)
	if !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("expected errInvalidCredentials, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < minAuthRejectDelay {
		t.Fatalf("expected at least %v delay, got %v", minAuthRejectDelay, elapsed)
	}
}

func TestRejectAuthReturnsImmediatelyAfterFloor(t *testing.T) {
	start := time.Now().Add(-minAuthRejectDelay - 20*time.Millisecond)
	callStart := time.Now()
	_, err := rejectAuth(start)
	if !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("expected errInvalidCredentials, got %v", err)
	}
	if elapsed := time.Since(callStart); elapsed > 75*time.Millisecond {
		t.Fatalf("expected fast return when floor already elapsed, got %v", elapsed)
	}
}
