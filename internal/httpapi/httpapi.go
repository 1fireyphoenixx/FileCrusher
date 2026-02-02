package httpapi

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"filecrusher/internal/fsutil"
	"filecrusher/internal/validate"
	"filecrusher/internal/webdavserver"
	"filecrusher/internal/webui"
	"golang.org/x/crypto/ssh"
)

// Server exposes the HTTPS API for users and administrators.
// It owns rate limiters and shared dependencies like DB and logger.
type Server struct {
	DB             *db.DB
	BindAddr       string
	Port           int
	CertPath       string
	KeyPath        string
	Logger         *slog.Logger
	MaxUploadBytes int64

	WebDAVEnable bool
	WebDAVPrefix string

	adminLimiter *fixedWindowLimiter
	userLimiter  *fixedWindowLimiter
}

const (
	maxJSONBytes = int64(64 << 10) // 64 KiB
)

// ListenAndServeTLS initializes handlers and starts the HTTPS server.
func (s *Server) ListenAndServeTLS() error {
	if s.DB == nil {
		return errors.New("db is required")
	}
	if s.CertPath == "" || s.KeyPath == "" {
		return errors.New("tls cert and key are required")
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.MaxUploadBytes == 0 {
		s.MaxUploadBytes = int64(512 << 20)
	}
	if s.adminLimiter == nil {
		s.adminLimiter = newFixedWindowLimiter(60, 1*time.Minute)
	}
	if s.userLimiter == nil {
		s.userLimiter = newFixedWindowLimiter(120, 1*time.Minute)
	}

	mux := http.NewServeMux()
	staticFS, err := fs.Sub(webui.StaticFS, "static")
	if err != nil {
		return err
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("/", s.serveIndex)

	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/files", s.withUser(s.handleFiles))
	mux.HandleFunc("/api/upload", s.withUser(s.handleUpload))
	mux.HandleFunc("/api/download", s.withUser(s.handleDownload))

	// Admin API
	mux.HandleFunc("/api/admin/login", s.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", s.withAdmin(s.handleAdminLogout))
	mux.HandleFunc("/api/admin/users", s.withAdmin(s.handleAdminUsers))
	mux.HandleFunc("/api/admin/users/", s.withAdmin(s.handleAdminUserByID))
	mux.HandleFunc("/api/admin/ip-allowlist", s.withAdmin(s.handleAdminAllowlist))
	mux.HandleFunc("/api/admin/ip-allowlist/", s.withAdmin(s.handleAdminAllowlistByID))

	if s.WebDAVEnable {
		prefix := s.WebDAVPrefix
		if prefix == "" {
			prefix = "/webdav"
		}
		davHandler := &webdavserver.Handler{
			DB:             s.DB,
			Prefix:         prefix,
			Logger:         s.Logger,
			MaxUploadBytes: s.MaxUploadBytes,
			Limiter:        s.userLimiter,
		}
		mux.Handle(prefix+"/", davHandler)
		s.Logger.Info("webdav enabled", "prefix", prefix)
	}

	h := withSecurityHeaders(mux)
	h = s.withRecover(h)
	h = s.withRequestLog(h)
	addr := s.BindAddr + ":" + strconv.Itoa(s.Port)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           h,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 5 * time.Second,
		// NOTE: Avoid ReadTimeout/WriteTimeout here; this server supports large uploads.
		// ReadHeaderTimeout + IdleTimeout are still enforced.
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}

	return httpServer.ListenAndServeTLS(s.CertPath, s.KeyPath)
}

// serveIndex serves the embedded admin web UI landing page.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webui.StaticFS.ReadFile("static/index.html")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "web ui missing"})
		return
	}
	w.Header().Set("content-type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// handleLogin authenticates a user and issues a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.Logger.Debug("login start", "remote_ip", clientIP(r))
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if ok, wait := s.userLimiter.Allow("user_login:" + clientIP(r)); !ok {
		w.Header().Set("retry-after", strconv.Itoa(int(wait.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBytes)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing credentials"})
		return
	}
	s.Logger.Debug("login parsed", "username", req.Username)

	ctx := r.Context()
	startDB := time.Now()
	u, ok, err := s.DB.GetUserByUsername(ctx, req.Username)
	if err != nil {
		s.Logger.Error("login db error", "op", "GetUserByUsername", "username", req.Username, "err", err.Error(), "ms", time.Since(startDB).Milliseconds())
		if isRetryableDBErr(err) {
			w.Header().Set("retry-after", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily unavailable"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	if !ok || !u.Enabled {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	s.Logger.Debug("login user ok", "username", u.Username, "user_id", u.ID, "ms", time.Since(startDB).Milliseconds())
	okPw, err := auth.VerifyPassword(req.Password, u.PassHash)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if !okPw {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	tok, err := auth.NewToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	startSess := time.Now()
	if err := s.DB.CreateSession(ctx, tok, "user", u.ID, 12*time.Hour); err != nil {
		s.Logger.Error("login db error", "op", "CreateSession", "user_id", u.ID, "err", err.Error(), "ms", time.Since(startSess).Milliseconds())
		if isRetryableDBErr(err) {
			w.Header().Set("retry-after", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily unavailable"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	s.Logger.Debug("login session created", "user_id", u.ID, "ms", time.Since(startSess).Milliseconds())

	setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// handleLogout clears a user session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ctx := r.Context()
	if tok, ok := readSessionCookie(r); ok {
		_ = s.DB.DeleteSession(ctx, tok)
	}
	clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// handleAdminLogin authenticates an admin and issues an admin cookie.
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	allowed, err := isAdminAllowedByIP(s.DB, r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access denied"})
		return
	}
	if ok, wait := s.adminLimiter.Allow("admin_login:" + clientIP(r)); !ok {
		w.Header().Set("retry-after", strconv.Itoa(int(wait.Seconds())))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBytes)
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing credentials"})
		return
	}

	hash, ok, err := s.DB.GetAdminPasswordHash(r.Context())
	if err != nil || !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin not configured"})
		return
	}
	okPw, err := auth.VerifyPassword(req.Password, hash)
	if err != nil || !okPw {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	tok, err := auth.NewToken(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	if err := s.DB.CreateSession(r.Context(), tok, "admin", 1, 12*time.Hour); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	setAdminCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// handleAdminLogout clears the admin session cookie.
func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if tok, ok := readAdminCookie(r); ok {
		_ = s.DB.DeleteSession(r.Context(), tok)
	}
	clearAdminCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// withAdmin enforces allowlist, rate limit, and admin authentication.
func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowed, err := isAdminAllowedByIP(s.DB, r)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		if !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin access denied"})
			return
		}
		if ok, wait := s.adminLimiter.Allow("admin:" + clientIP(r)); !ok {
			w.Header().Set("retry-after", strconv.Itoa(int(wait.Seconds())))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
			return
		}
		tok, ok := readAdminCookie(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		sess, ok, err := s.DB.GetSession(r.Context(), tok)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		if !ok || sess.Kind != "admin" || sess.ExpiresAt <= time.Now().Unix() {
			clearAdminCookie(w)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		next(w, r)
	}
}

// handleAdminAllowlist lists or adds admin IP allowlist entries.
func (s *Server) handleAdminAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries, err := s.DB.ListAdminIPAllowlist(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBytes)
		var req struct {
			CIDR string `json:"cidr"`
			Note string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		n, err := parseCIDRorIP(req.CIDR)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cidr"})
			return
		}
		id, err := s.DB.AddAdminIPAllowlist(r.Context(), n.String(), strings.TrimSpace(req.Note))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "add failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "cidr": n.String()})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAdminAllowlistByID deletes an allowlist entry by ID.
func (s *Server) handleAdminAllowlistByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/admin/ip-allowlist/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := s.DB.DeleteAdminIPAllowlist(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// handleAdminUsers lists existing users or creates new users.
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.DB.ListUsers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		type item struct {
			ID          int64  `json:"id"`
			Username    string `json:"username"`
			RootPath    string `json:"root_path"`
			Enabled     bool   `json:"enabled"`
			AllowSFTP   bool   `json:"allow_sftp"`
			AllowFTP    bool   `json:"allow_ftp"`
			AllowFTPS   bool   `json:"allow_ftps"`
			AllowSCP    bool   `json:"allow_scp"`
			AllowWebDAV bool   `json:"allow_webdav"`
			CreatedAt   int64  `json:"created_at"`
			UpdatedAt   int64  `json:"updated_at"`
		}
		out := make([]item, 0, len(users))
		for _, u := range users {
			out = append(out, item{
				ID:          u.ID,
				Username:    u.Username,
				RootPath:    u.RootPath,
				Enabled:     u.Enabled,
				AllowSFTP:   u.AllowSFTP,
				AllowFTP:    u.AllowFTP,
				AllowFTPS:   u.AllowFTPS,
				AllowSCP:    u.AllowSCP,
				AllowWebDAV: u.AllowWebDAV,
				CreatedAt:   u.CreatedAt,
				UpdatedAt:   u.UpdatedAt,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
	case http.MethodPost:
		var req struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			RootPath    string `json:"root_path"`
			AllowSFTP   bool   `json:"allow_sftp"`
			AllowFTP    bool   `json:"allow_ftp"`
			AllowFTPS   bool   `json:"allow_ftps"`
			AllowSCP    bool   `json:"allow_scp"`
			AllowWebDAV bool   `json:"allow_webdav"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if err := validate.Username(req.Username); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
			return
		}
		root, err := validate.RootPath(req.RootPath)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		h, err := auth.HashPassword(req.Password, auth.DefaultArgon2Params())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		id, err := s.DB.CreateUser(r.Context(), req.Username, h, root, req.AllowSFTP, req.AllowFTP, req.AllowFTPS, req.AllowSCP, req.AllowWebDAV)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "create user failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAdminUserByID updates, deletes, or manages a specific user.
func (s *Server) handleAdminUserByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || userID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPut:
			var req struct {
				RootPath    string `json:"root_path"`
				Enabled     bool   `json:"enabled"`
				AllowSFTP   bool   `json:"allow_sftp"`
				AllowFTP    bool   `json:"allow_ftp"`
				AllowFTPS   bool   `json:"allow_ftps"`
				AllowSCP    bool   `json:"allow_scp"`
				AllowWebDAV bool   `json:"allow_webdav"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
				return
			}
			root, err := validate.RootPath(req.RootPath)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if err := s.DB.UpdateUser(r.Context(), userID, root, req.Enabled, req.AllowSFTP, req.AllowFTP, req.AllowFTPS, req.AllowSCP, req.AllowWebDAV); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		case http.MethodDelete:
			if err := s.DB.DeleteUser(r.Context(), userID); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}

	if len(parts) == 2 && parts[1] == "password" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		if req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
			return
		}
		h, err := auth.HashPassword(req.Password, auth.DefaultArgon2Params())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		if err := s.DB.SetUserPasswordHash(r.Context(), userID, h); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		return
	}

	if len(parts) >= 2 && parts[1] == "keys" {
		if len(parts) == 2 {
			switch r.Method {
			case http.MethodGet:
				keys, err := s.DB.ListSSHKeysForUser(r.Context(), userID)
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
			case http.MethodPost:
				var req struct {
					PublicKey string `json:"public_key"`
					Comment   string `json:"comment"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
					return
				}
				pub := strings.TrimSpace(req.PublicKey)
				if pub == "" {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "public_key is required"})
					return
				}
				key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public key"})
					return
				}
				fp := ssh.FingerprintSHA256(key)
				keyID, err := s.DB.AddSSHKey(r.Context(), userID, pub, fp, strings.TrimSpace(req.Comment))
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "add key failed"})
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"id": keyID, "fingerprint": fp})
			default:
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			}
			return
		}
		if len(parts) == 3 {
			keyID, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil || keyID <= 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid key id"})
				return
			}
			if r.Method != http.MethodDelete {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			if err := s.DB.DeleteSSHKeyForUser(r.Context(), userID, keyID); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
			return
		}
	}

	http.NotFound(w, r)
}

// ctxKey is a typed context key for user metadata.
type ctxKey string

const (
	ctxUserID   ctxKey = "user_id"
	ctxUserRoot ctxKey = "user_root"
)

// withUser enforces user authentication and injects user context.
func (s *Server) withUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := readSessionCookie(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		sess, ok, err := s.DB.GetSession(r.Context(), tok)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		if !ok || sess.Kind != "user" || sess.ExpiresAt <= time.Now().Unix() {
			clearSessionCookie(w)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}

		u, ok, err := s.DB.GetUserByID(r.Context(), sess.SubjectID)
		if err != nil || !ok || !u.Enabled {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}

		ctx := context.WithValue(r.Context(), ctxUserID, sess.SubjectID)
		ctx = context.WithValue(ctx, ctxUserRoot, u.RootPath)
		next(w, r.WithContext(ctx))
	}
}

// handleFiles lists directories, creates folders, or deletes paths.
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if r.Method == http.MethodDelete || r.Method == http.MethodPost {
		p := strings.TrimSpace(path)
		if p == "" || p == "/" {
			if r.Method == http.MethodDelete {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refusing to delete root"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refusing to create root"})
			return
		}
	}
	root := r.Context().Value(ctxUserRoot).(string)
	local, err := fsutil.ResolveWithinRoot(root, path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		entries, err := os.ReadDir(local)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not a directory"})
			return
		}
		type item struct {
			Name    string `json:"name"`
			IsDir   bool   `json:"is_dir"`
			Size    int64  `json:"size"`
			ModTime int64  `json:"mod_time"`
		}
		out := make([]item, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, item{
				Name:    e.Name(),
				IsDir:   e.IsDir(),
				Size:    info.Size(),
				ModTime: info.ModTime().Unix(),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": out})
	case http.MethodPost:
		if st, err := os.Stat(local); err == nil {
			if !st.IsDir() {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path exists and is not a directory"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
			return
		} else if err != nil && !os.IsNotExist(err) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "mkdir failed"})
			return
		}
		if err := os.MkdirAll(local, 0o700); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mkdir failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	case http.MethodDelete:
		if err := os.RemoveAll(local); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleUpload stores a single uploaded file within the user's root.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxUploadBytes)
	root := r.Context().Value(ctxUserRoot).(string)
	base := r.URL.Query().Get("path")
	dir, err := fsutil.ResolveWithinRoot(root, base)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upload failed"})
		return
	}

	file, hdr, err := readMultipartFile(r, "file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file"})
		return
	}
	defer file.Close()

	name := filepath.Base(hdr.Filename)
	if name == "." || name == string(filepath.Separator) || name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid filename"})
		return
	}
	dstPath, err := fsutil.ResolveWithinRoot(root, filepath.ToSlash(filepath.Join(strings.TrimLeft(base, "/"), name)))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid filename"})
		return
	}

	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upload failed"})
		return
	}
	defer f.Close()

	if _, err := io.Copy(f, file); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upload failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

// handleDownload serves a file or zips a directory for download.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	root := r.Context().Value(ctxUserRoot).(string)
	userPath := r.URL.Query().Get("path")
	local, err := fsutil.ResolveWithinRoot(root, userPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	st, err := os.Stat(local)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if st.IsDir() {
		zipBase := zipBaseName(userPath)
		s.serveZipDir(w, local, zipBase)
		return
	}

	name := filepath.Base(local)
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("content-disposition", "attachment; filename=\""+escapeQuotes(name)+"\"")
	http.ServeFile(w, r, local)
}

// zipBaseName chooses a safe base name for zipped folders.
func zipBaseName(userPath string) string {
	p := strings.TrimSpace(userPath)
	if p == "" || p == "/" {
		return "root"
	}
	// Use URL-path semantics, not OS path semantics.
	p = "/" + strings.Trim(p, "/")
	base := pathpkg.Base(p)
	base = strings.TrimSpace(base)
	base = strings.Trim(base, "/")
	if base == "" || base == "." || base == ".." {
		return "folder"
	}
	return base
}

// serveZipDir streams a directory as a ZIP archive.
func (s *Server) serveZipDir(w http.ResponseWriter, dir string, zipBase string) {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	zipBase = strings.TrimSpace(zipBase)
	zipBase = strings.Trim(zipBase, "/")
	if zipBase == "" {
		zipBase = "folder"
	}
	zipFile := zipBase + ".zip"

	w.Header().Set("content-type", "application/zip")
	w.Header().Set("content-disposition", "attachment; filename=\""+escapeQuotes(zipFile)+"\"")

	zw := zip.NewWriter(w)
	defer func() { _ = zw.Close() }()

	prefix := zipBase
	// Ensure empty folders round-trip.
	_, _ = zw.Create(prefix + "/")

	fsys := os.DirFS(dir)
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			s.Logger.Error("zip walk error", "dir", dir, "path", p, "err", err.Error())
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == "." {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// Never follow symlinks when zipping.
			return nil
		}
		info, err := d.Info()
		if err != nil {
			s.Logger.Error("zip stat error", "dir", dir, "path", p, "err", err.Error())
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		name := filepath.ToSlash(p)
		name = strings.TrimPrefix(name, "./")
		if strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
			return nil
		}
		zipPath := prefix + "/" + name

		if d.IsDir() {
			hdr, err := zip.FileInfoHeader(info)
			if err != nil {
				return nil
			}
			hdr.Name = zipPath + "/"
			hdr.Method = zip.Store
			_, _ = zw.CreateHeader(hdr)
			return nil
		}

		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return nil
		}
		hdr.Name = zipPath
		hdr.Method = zip.Store
		wr, err := zw.CreateHeader(hdr)
		if err != nil {
			s.Logger.Error("zip create error", "dir", dir, "path", p, "err", err.Error())
			return nil
		}

		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil {
			s.Logger.Error("zip open error", "dir", dir, "path", p, "err", err.Error())
			return nil
		}
		defer f.Close()
		_, _ = io.Copy(wr, f)
		return nil
	})
}

// readMultipartFile parses and returns the uploaded file for a form field.
func readMultipartFile(r *http.Request, field string) (multipart.File, *multipart.FileHeader, error) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		return nil, nil, err
	}
	return r.FormFile(field)
}

// escapeQuotes strips quotes from a header filename value.
func escapeQuotes(s string) string {
	return strings.ReplaceAll(s, "\"", "")
}

// setSessionCookie writes the user session cookie.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "fc_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
}

// clearSessionCookie deletes the user session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "fc_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// setAdminCookie writes the admin session cookie.
func setAdminCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "fc_admin",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
}

// clearAdminCookie deletes the admin session cookie.
func clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "fc_admin",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// readAdminCookie returns the admin session token from cookies.
func readAdminCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie("fc_admin")
	if err != nil {
		return "", false
	}
	if c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// readSessionCookie returns the user session token from cookies.
func readSessionCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie("fc_session")
	if err != nil {
		return "", false
	}
	if c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// writeJSON sends a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// withSecurityHeaders adds common security headers for browser clients.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-content-type-options", "nosniff")
		w.Header().Set("x-frame-options", "DENY")
		w.Header().Set("referrer-policy", "no-referrer")
		w.Header().Set("content-security-policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			w.Header().Set("strict-transport-security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
