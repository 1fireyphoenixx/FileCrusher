package webdavserver

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"golang.org/x/net/webdav"
)

type Handler struct {
	DB     *db.DB
	Prefix string
	Logger *slog.Logger

	once sync.Once
	ls   webdav.LockSystem
}

func (h *Handler) lockSystem() webdav.LockSystem {
	h.once.Do(func() {
		h.ls = webdav.NewMemLS()
	})
	return h.ls
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lg := h.Logger
	if lg == nil {
		lg = slog.Default()
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
