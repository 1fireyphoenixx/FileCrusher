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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

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
