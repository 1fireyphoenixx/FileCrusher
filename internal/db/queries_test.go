// Package db tests verify database CRUD behavior.
package db

import (
	"context"
	"testing"
)

// TestUserProtocolFlagsRoundTrip ensures boolean flags survive DB storage.
func TestUserProtocolFlagsRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, err := Open(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	_, err = d.CreateUser(ctx, "alice", "hash", t.TempDir(), 1234, true, true, false, true, true)
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
	if !u.AllowSFTP || !u.AllowFTP || u.AllowFTPS || !u.AllowSCP || !u.AllowWebDAV {
		t.Fatalf("unexpected flags: %+v", u)
	}
	if u.QuotaBytes != 1234 {
		t.Fatalf("unexpected quota: %d", u.QuotaBytes)
	}
}

// TestAdminAllowlistCRUD covers basic allowlist insert/list/delete operations.
func TestAdminAllowlistCRUD(t *testing.T) {
	ctx := context.Background()
	d, err := Open(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	id, err := d.AddAdminIPAllowlist(ctx, "127.0.0.1/32", "local")
	if err != nil {
		t.Fatalf("AddAdminIPAllowlist: %v", err)
	}
	entries, err := d.ListAdminIPAllowlist(ctx)
	if err != nil {
		t.Fatalf("ListAdminIPAllowlist: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != id {
		t.Fatalf("unexpected id")
	}
	if err := d.DeleteAdminIPAllowlist(ctx, id); err != nil {
		t.Fatalf("DeleteAdminIPAllowlist: %v", err)
	}
}

func TestUserQuotaRejectsNegative(t *testing.T) {
	ctx := context.Background()
	d, err := Open(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	_, err = d.CreateUser(ctx, "bob", "hash", t.TempDir(), -1, true, false, false, false, false)
	if err == nil {
		t.Fatalf("expected create error for negative quota")
	}
}
