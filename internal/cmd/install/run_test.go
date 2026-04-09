package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRunScriptUnix(t *testing.T) {
	dir := t.TempDir()
	cmd := filepath.Join(dir, "run.cmd")
	if err := os.WriteFile(cmd, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed run.cmd: %v", err)
	}

	if err := writeRunScript(dir, "linux"); err != nil {
		t.Fatalf("writeRunScript linux: %v", err)
	}

	sh := filepath.Join(dir, "run.sh")
	if _, err := os.Stat(sh); err != nil {
		t.Fatalf("missing run.sh: %v", err)
	}
	if _, err := os.Stat(cmd); !os.IsNotExist(err) {
		t.Fatalf("run.cmd should be removed, err=%v", err)
	}
}

func TestWriteRunScriptWindows(t *testing.T) {
	dir := t.TempDir()
	sh := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(sh, []byte("stale"), 0o755); err != nil {
		t.Fatalf("seed run.sh: %v", err)
	}

	if err := writeRunScript(dir, "windows"); err != nil {
		t.Fatalf("writeRunScript windows: %v", err)
	}

	cmd := filepath.Join(dir, "run.cmd")
	if _, err := os.Stat(cmd); err != nil {
		t.Fatalf("missing run.cmd: %v", err)
	}
	if _, err := os.Stat(sh); !os.IsNotExist(err) {
		t.Fatalf("run.sh should be removed, err=%v", err)
	}
}
