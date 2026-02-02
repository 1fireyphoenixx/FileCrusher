// Package webdavserver provides a WebDAV handler backed by FileCrusher users.
package webdavserver

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"golang.org/x/net/webdav"
)

// RateLimiter abstracts the rate limiting check.
type RateLimiter interface {
	Allow(key string) (bool, time.Duration)
}

// Handler authenticates users and serves WebDAV requests.
type Handler struct {
	DB             *db.DB
	Prefix         string
	Logger         *slog.Logger
	MaxUploadBytes int64
	Limiter        RateLimiter

	once sync.Once
	ls   webdav.LockSystem
}

// lockSystem lazily initializes the in-memory lock system.
func (h *Handler) lockSystem() webdav.LockSystem {
	h.once.Do(func() {
		h.ls = webdav.NewMemLS()
	})
	return h.ls
}

// ServeHTTP authenticates the request and proxies to webdav.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lg := h.Logger
	if lg == nil {
		lg = slog.Default()
	}

	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.Split(fwd, ",")[0]
	}

	if h.Limiter != nil {
		if ok, wait := h.Limiter.Allow("webdav:" + clientIP); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="FileCrusher WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	u, found, err := h.DB.GetUserByUsername(r.Context(), username)
	if err != nil {
		lg.Error("webdav db error", "err", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !found || !u.Enabled || !u.AllowWebDAV {
		w.Header().Set("WWW-Authenticate", `Basic realm="FileCrusher WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	okPw, err := auth.VerifyPassword(password, u.PassHash)
	if err != nil || !okPw {
		w.Header().Set("WWW-Authenticate", `Basic realm="FileCrusher WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if h.MaxUploadBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.MaxUploadBytes)
	}

	lg.Debug("webdav authenticated", "user", username, "method", r.Method, "path", r.URL.Path)

	fs := NewJailFS(u.RootPath)
	prefix := strings.TrimSuffix(h.Prefix, "/")

	dav := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: fs,
		LockSystem: h.lockSystem(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				lg.Warn("webdav request error", "method", r.Method, "path", r.URL.Path, "err", err.Error())
			}
		},
	}
	dav.ServeHTTP(w, r)
}
