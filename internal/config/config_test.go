// Package config tests validate config loading behavior.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadAppliesDefaults confirms defaults are applied on load.
func TestLoadAppliesDefaults(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "filecrusher.yaml")
	if err := os.WriteFile(p, []byte("db:\n  path: ./x.db\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.HTTP.Port != 5132 {
		t.Fatalf("expected default http.port 5132, got %d", c.HTTP.Port)
	}
	if c.HTTP.MaxUploadMB != 512 {
		t.Fatalf("expected default http.max_upload_mb 512, got %d", c.HTTP.MaxUploadMB)
	}
	if c.SSH.Port != 2022 {
		t.Fatalf("expected default ssh.port 2022, got %d", c.SSH.Port)
	}
	if c.DataDir == "" {
		t.Fatalf("expected data_dir default")
	}
}
