// Package httpapi tests cover file and download handlers.
package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testLogger silences logs during handler tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

// TestHandleFiles_Mkdir creates a directory via the files handler.
func TestHandleFiles_Mkdir(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	r := httptest.NewRequest("POST", "/api/files?path=%2Fnewdir", nil)
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
	st, err := os.Stat(filepath.Join(tmp, "newdir"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("expected directory")
	}
}

// TestHandleFiles_Mkdir_RefusesRoot rejects creating the root path.
func TestHandleFiles_Mkdir_RefusesRoot(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	r := httptest.NewRequest("POST", "/api/files?path=%2F", nil)
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 400 {
		t.Fatalf("status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

// TestHandleFiles_Mkdir_PathExistsAsFile rejects mkdir on a file.
func TestHandleFiles_Mkdir_PathExistsAsFile(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	if err := os.WriteFile(filepath.Join(tmp, "x"), []byte("nope"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}

	r := httptest.NewRequest("POST", "/api/files?path=%2Fx", nil)
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 400 {
		t.Fatalf("status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

// TestHandleFiles_Rename renames a file via PATCH.
func TestHandleFiles_Rename(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	if err := os.WriteFile(filepath.Join(tmp, "old.txt"), []byte("data"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}

	body := strings.NewReader(`{"name":"new.txt"}`)
	r := httptest.NewRequest("PATCH", "/api/files?path=%2Fold.txt", body)
	r.Header.Set("content-type", "application/json")
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
	if _, err := os.Stat(filepath.Join(tmp, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("old file should not exist")
	}
	if _, err := os.Stat(filepath.Join(tmp, "new.txt")); err != nil {
		t.Fatalf("new file should exist: %v", err)
	}
}

// TestHandleFiles_Rename_Dir renames a directory via PATCH.
func TestHandleFiles_Rename_Dir(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	if err := os.MkdirAll(filepath.Join(tmp, "olddir"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	body := strings.NewReader(`{"name":"newdir"}`)
	r := httptest.NewRequest("PATCH", "/api/files?path=%2Folddir", body)
	r.Header.Set("content-type", "application/json")
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
	st, err := os.Stat(filepath.Join(tmp, "newdir"))
	if err != nil {
		t.Fatalf("newdir should exist: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("expected directory")
	}
}

// TestHandleFiles_Rename_Conflict rejects rename when destination exists.
func TestHandleFiles_Rename_Conflict(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	if err := os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}

	body := strings.NewReader(`{"name":"b.txt"}`)
	r := httptest.NewRequest("PATCH", "/api/files?path=%2Fa.txt", body)
	r.Header.Set("content-type", "application/json")
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 400 {
		t.Fatalf("expected 400, got status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

// TestHandleFiles_Rename_InvalidName rejects traversal names.
func TestHandleFiles_Rename_InvalidName(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	if err := os.WriteFile(filepath.Join(tmp, "x.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}

	for _, bad := range []string{"", ".", "..", "../etc", "a/b"} {
		body := strings.NewReader(`{"name":"` + bad + `"}`)
		r := httptest.NewRequest("PATCH", "/api/files?path=%2Fx.txt", body)
		r.Header.Set("content-type", "application/json")
		ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
		w := httptest.NewRecorder()
		s.handleFiles(w, r.WithContext(ctx))

		if w.Code != 400 {
			t.Fatalf("name=%q: expected 400, got status=%d body=%s", bad, w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
}

// TestHandleFiles_Rename_Root rejects renaming root.
func TestHandleFiles_Rename_Root(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	body := strings.NewReader(`{"name":"x"}`)
	r := httptest.NewRequest("PATCH", "/api/files?path=%2F", body)
	r.Header.Set("content-type", "application/json")
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 400 {
		t.Fatalf("expected 400, got status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

// TestHandleFiles_Rename_NotFound rejects renaming a nonexistent path.
func TestHandleFiles_Rename_NotFound(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	body := strings.NewReader(`{"name":"y.txt"}`)
	r := httptest.NewRequest("PATCH", "/api/files?path=%2Fghost.txt", body)
	r.Header.Set("content-type", "application/json")
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleFiles(w, r.WithContext(ctx))

	if w.Code != 404 {
		t.Fatalf("expected 404, got status=%d body=%s", w.Code, strings.TrimSpace(w.Body.String()))
	}
}

// TestHandleDownload_DirectoryZip zips directories and skips symlinks.
func TestHandleDownload_DirectoryZip(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	docs := filepath.Join(tmp, "docs")
	if err := os.MkdirAll(docs, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docs, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Symlink("../outside.txt", filepath.Join(docs, "link"))
	}

	r := httptest.NewRequest("GET", "/api/download?path=%2Fdocs", nil)
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleDownload(w, r.WithContext(ctx))

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	ct := w.Header().Get("content-type")
	if !strings.Contains(ct, "application/zip") {
		t.Fatalf("content-type=%q", ct)
	}

	b := w.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}

	var names []string
	var gotA string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if f.Name == "docs/a.txt" {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			data, _ := io.ReadAll(rc)
			_ = rc.Close()
			gotA = string(data)
		}
	}
	if gotA != "hello" {
		t.Fatalf("docs/a.txt=%q", gotA)
	}
	for _, n := range names {
		if strings.HasSuffix(n, "/link") {
			t.Fatalf("symlink should not be included: %q", n)
		}
	}
}

// TestHandleDownload_RootZip uses a stable name for root zip downloads.
func TestHandleDownload_RootZip(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{Logger: testLogger()}

	if err := os.WriteFile(filepath.Join(tmp, "r.txt"), []byte("rootfile"), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}

	r := httptest.NewRequest("GET", "/api/download?path=%2F", nil)
	ctx := context.WithValue(r.Context(), ctxUserRoot, tmp)
	w := httptest.NewRecorder()
	s.handleDownload(w, r.WithContext(ctx))

	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}

	b := w.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}

	found := false
	for _, f := range zr.File {
		if f.Name == "root/r.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected root/r.txt in zip")
	}
}
