package webdavserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
)

func newDAVServer(t *testing.T) (*Handler, *http.Client, string, string) {
	t.Helper()
	d, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	hash, err := auth.HashPassword("password", auth.DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, u := range []struct {
		name         string
		enabled, dav bool
	}{{"alice", true, true}, {"bob", true, true}, {"disabled", false, true}, {"no-dav", true, false}} {
		userRoot := root
		if u.name != "alice" {
			userRoot = t.TempDir()
		}
		id, err := d.CreateUser(context.Background(), u.name, hash, userRoot, 0, false, false, false, false, u.dav)
		if err != nil {
			t.Fatal(err)
		}
		if !u.enabled {
			if err := d.UpdateUser(context.Background(), id, userRoot, 0, false, false, false, false, false, u.dav); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := &Handler{DB: d, Prefix: "/webdav", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), MaxUploadBytes: 1024}
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.Timeout = 5 * time.Second
	return h, client, ts.URL, root
}

func davRequest(t *testing.T, c *http.Client, method, url, body, user, password string, want int, headers map[string]string) (http.Header, string) {
	t.Helper()
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		r.SetBasicAuth(user, password)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status=%d want=%d body=%s", method, url, resp.StatusCode, want, b)
	}
	return resp.Header, string(b)
}

func TestDAVAuthentication(t *testing.T) {
	_, c, url, _ := newDAVServer(t)
	for _, tc := range []struct{ name, user, password string }{
		{"missing", "", ""}, {"unknown", "unknown", "password"}, {"wrong password", "alice", "wrong"}, {"disabled", "disabled", "password"}, {"protocol disabled", "no-dav", "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers, _ := davRequest(t, c, "PROPFIND", url+"/webdav/", "", tc.user, tc.password, 401, nil)
			if headers.Get("WWW-Authenticate") == "" {
				t.Fatal("missing authentication challenge")
			}
		})
	}
}

func TestDAVAuthenticatedFileLifecycleAndIsolation(t *testing.T) {
	_, c, url, root := newDAVServer(t)
	davRequest(t, c, "MKCOL", url+"/webdav/docs", "", "alice", "password", 201, nil)
	davRequest(t, c, "PUT", url+"/webdav/docs/file.txt", "transfer payload", "alice", "password", 201, nil)
	_, body := davRequest(t, c, "GET", url+"/webdav/docs/file.txt", "", "alice", "password", 200, nil)
	if body != "transfer payload" {
		t.Fatalf("download corrupted: %q", body)
	}
	disk, err := os.ReadFile(filepath.Join(root, "docs", "file.txt"))
	if err != nil || string(disk) != body {
		t.Fatalf("disk contents: %q, %v", disk, err)
	}
	davRequest(t, c, "GET", url+"/webdav/docs/file.txt", "", "bob", "password", 404, nil)
	davRequest(t, c, "MOVE", url+"/webdav/docs/file.txt", "", "alice", "password", 201, map[string]string{"Destination": url + "/webdav/docs/renamed.txt"})
	davRequest(t, c, "GET", url+"/webdav/docs/file.txt", "", "alice", "password", 404, nil)
	_, body = davRequest(t, c, "GET", url+"/webdav/docs/renamed.txt", "", "alice", "password", 200, nil)
	if body != "transfer payload" {
		t.Fatal("move corrupted contents")
	}
	davRequest(t, c, "DELETE", url+"/webdav/docs/renamed.txt", "", "alice", "password", 204, nil)
	davRequest(t, c, "GET", url+"/webdav/docs/renamed.txt", "", "alice", "password", 404, nil)
}

func TestDAVRootDeletionAndSymlinkEscape(t *testing.T) {
	_, c, url, root := newDAVServer(t)
	davRequest(t, c, "DELETE", url+"/webdav/", "", "alice", "password", 405, nil)
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("root removed: %v", err)
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		req, err := http.NewRequest(method, url+"/webdav/escape/secret.txt", strings.NewReader("overwrite"))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("alice", "password")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode < 400 || strings.Contains(string(body), "private") {
			t.Fatalf("%s escaped jail: %d %s", method, resp.StatusCode, body)
		}
	}
	b, err := os.ReadFile(secret)
	if err != nil || string(b) != "private" {
		t.Fatalf("outside file changed: %q %v", b, err)
	}
}
