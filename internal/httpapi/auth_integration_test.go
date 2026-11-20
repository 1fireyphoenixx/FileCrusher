package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
)

// Use the production router and a real temporary SQLite database. Requests do
// not inject authentication context or bypass the authorization middleware.
func newAuthServer(t *testing.T) (*Server, http.Handler, int64, string) {
	t.Helper()
	d, err := db.Open(context.Background(), t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	hash, err := auth.HashPassword("test-password", auth.DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	id, err := d.CreateUser(context.Background(), "alice", hash, root, 0, true, true, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetAdminPasswordHash(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: d, Logger: testLogger()}
	h, err := s.handler()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.userLimiter.Stop)
	t.Cleanup(s.adminLimiter.Stop)
	return s, h, id, root
}

func authRequest(t *testing.T, h http.Handler, method, path, body string, cookie *http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	return w
}

func loginCookie(t *testing.T, h http.Handler, admin bool) *http.Cookie {
	t.Helper()
	path, body := "/api/login", `{"username":"alice","password":"test-password"}`
	if admin {
		path, body = "/api/admin/login", `{"password":"test-password"}`
	}
	w := authRequest(t, h, "POST", path, body, nil, 200)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected session cookie, got %v", cookies)
	}
	c := cookies[0]
	if c.Value == "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("unsafe session cookie: %+v", c)
	}
	return c
}

func TestSessionLifecycle(t *testing.T) {
	for _, admin := range []bool{false, true} {
		t.Run(fmt.Sprint("admin=", admin), func(t *testing.T) {
			s, h, _, _ := newAuthServer(t)
			path, logout := "/api/files?path=/", "/api/logout"
			if admin {
				path, logout = "/api/admin/users", "/api/admin/logout"
			}
			authRequest(t, h, "GET", path, "", nil, 401)
			c := loginCookie(t, h, admin)
			// Exercise both the DB lookup and the cached session path.
			for i := 0; i < 2; i++ {
				authRequest(t, h, "GET", path, "", c, 200)
			}
			w := authRequest(t, h, "POST", logout, "", c, 200)
			if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 {
				t.Fatal("logout did not expire cookie")
			}
			authRequest(t, h, "GET", path, "", c, 401)
			if _, ok, err := s.DB.GetSession(context.Background(), c.Value); err != nil || ok {
				t.Fatalf("session survived logout: found=%v err=%v", ok, err)
			}
		})
	}
}

func TestSessionRejectsExpiredUnknownAndWrongRole(t *testing.T) {
	s, h, id, _ := newAuthServer(t)
	for _, tc := range []struct {
		name, kind, cookie, path string
		ttl                      time.Duration
	}{
		{"expired user", "user", "fc_session", "/api/files", -time.Hour},
		{"expired admin", "admin", "fc_admin", "/api/admin/users", -time.Hour},
		{"user as admin", "user", "fc_admin", "/api/admin/users", time.Hour},
		{"admin as user", "admin", "fc_session", "/api/files", time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.DB.CreateSession(context.Background(), tc.name, tc.kind, id, tc.ttl); err != nil {
				t.Fatal(err)
			}
			authRequest(t, h, "GET", tc.path, "", &http.Cookie{Name: tc.cookie, Value: tc.name}, 401)
		})
	}
	authRequest(t, h, "GET", "/api/files", "", &http.Cookie{Name: "fc_session", Value: "unknown"}, 401)
}

func TestLoginRejectsBadCredentialsAndMalformedInput(t *testing.T) {
	_, h, _, _ := newAuthServer(t)
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"wrong password", `{"username":"alice","password":"wrong"}`, 401},
		{"unknown user", `{"username":"nobody","password":"wrong"}`, 401},
		{"missing password", `{"username":"alice"}`, 400},
		{"malformed", "{", 400},
		{"oversized", `{"username":"` + strings.Repeat("a", int(maxJSONBytes)) + `","password":"x"}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := authRequest(t, h, "POST", "/api/login", tc.body, nil, tc.status)
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("failed login issued cookie")
			}
		})
	}
	authRequest(t, h, "GET", "/api/login", "", nil, 405)
}

func TestAdminAccountChangesRevokeCachedAccess(t *testing.T) {
	for _, method := range []string{"PUT", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			_, h, id, root := newAuthServer(t)
			user, admin := loginCookie(t, h, false), loginCookie(t, h, true)
			authRequest(t, h, "GET", "/api/files", "", user, 200)
			body, err := json.Marshal(map[string]any{"root_path": root, "enabled": false})
			if err != nil {
				t.Fatal(err)
			}
			authRequest(t, h, method, fmt.Sprintf("/api/admin/users/%d", id), string(body), admin, 200)
			authRequest(t, h, "GET", "/api/files", "", user, 401)
			authRequest(t, h, "POST", "/api/login", `{"username":"alice","password":"test-password"}`, nil, 401)
		})
	}
}

func TestAdminAllowlistAndForwardedHeader(t *testing.T) {
	_, h, _, _ := newAuthServer(t)
	for _, addr := range []string{"192.0.2.10:1234", "[2001:db8::1]:1234"} {
		r := httptest.NewRequest("POST", "/api/admin/login", strings.NewReader(`{"password":"test-password"}`))
		r.RemoteAddr = addr
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("remote %s bypassed allowlist: %d", addr, w.Code)
		}
	}
	admin := loginCookie(t, h, true) // Populate the default allowlist cache.
	authRequest(t, h, "POST", "/api/admin/ip-allowlist", `{"cidr":"192.0.2.0/24"}`, admin, 200)
	authRequest(t, h, "GET", "/api/admin/users", "", admin, 403) // Cache must be invalidated immediately.
	r := httptest.NewRequest("GET", "/api/admin/users", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.AddCookie(admin)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("allowlisted address denied: %d %s", w.Code, w.Body.String())
	}
}

func TestLoginRateLimit(t *testing.T) {
	s, h, _, _ := newAuthServer(t)
	s.userLimiter.max = 1
	authRequest(t, h, "POST", "/api/login", "{}", nil, 400)
	w := authRequest(t, h, "POST", "/api/login", "{}", nil, 429)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func TestCachedSessionCannotOutliveExpiry(t *testing.T) {
	for _, admin := range []bool{false, true} {
		t.Run(fmt.Sprint("admin=", admin), func(t *testing.T) {
			s, h, _, _ := newAuthServer(t)
			c := loginCookie(t, h, admin)
			path := "/api/files"
			if admin {
				path = "/api/admin/users"
			}
			authRequest(t, h, "GET", path, "", c, 200)
			// Expire both the persisted and cached grant without sleeping for 12 hours.
			cs, ok := s.getCachedSession(c.Value)
			if !ok {
				t.Fatal("session was not cached")
			}
			if err := s.DB.DeleteSession(context.Background(), c.Value); err != nil {
				t.Fatal(err)
			}
			if err := s.DB.CreateSession(context.Background(), c.Value, cs.session.Kind, cs.session.SubjectID, -time.Hour); err != nil {
				t.Fatal(err)
			}
			cs.session.ExpiresAt = time.Now().Add(-time.Hour).Unix()
			authRequest(t, h, "GET", path, "", c, 401)
		})
	}
}
