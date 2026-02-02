package db

import (
	"context"
	"testing"
)

func TestUserProtocolFlagsRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, err := Open(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	_, err = d.CreateUser(ctx, "alice", "hash", t.TempDir(), true, true, false, true)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, ok, err := d.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if !ok {
		t.Fatalf("expected user")
	}
	if !u.AllowSFTP || !u.AllowFTP || u.AllowFTPS || !u.AllowSCP {
		t.Fatalf("unexpected flags: %+v", u)
	}
}
