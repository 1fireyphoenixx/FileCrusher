package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filecrusher/internal/auth"
	"filecrusher/internal/db"
	"filecrusher/internal/fsutil"
	"filecrusher/internal/validate"
	"filecrusher/internal/webui"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	DB       *db.DB
	BindAddr string
	Port     int
	CertPath string
	KeyPath  string
}

func (s *Server) ListenAndServeTLS() error {
	if s.DB == nil {
		return errors.New("db is required")
	}
	if s.CertPath == "" || s.KeyPath == "" {
		return errors.New("tls cert and key are required")
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
	mux.HandleFunc("/api/admin/logout", s.handleAdminLogout)
	mux.HandleFunc("/api/admin/users", s.withAdmin(s.handleAdminUsers))
	mux.HandleFunc("/api/admin/users/", s.withAdmin(s.handleAdminUserByID))

	h := withSecurityHeaders(mux)
	addr := s.BindAddr + ":" + strconv.Itoa(s.Port)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return httpServer.ListenAndServeTLS(s.CertPath, s.KeyPath)
}

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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

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

	ctx := r.Context()
	u, ok, err := s.DB.GetUserByUsername(ctx, req.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}
	if !ok || !u.Enabled {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
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
	if err := s.DB.CreateSession(ctx, tok, "user", u.ID, 12*time.Hour); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}

	setSessionCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

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

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.DB.ListUsers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			return
		}
		type item struct {
			ID        int64  `json:"id"`
			Username  string `json:"username"`
			RootPath  string `json:"root_path"`
			Enabled   bool   `json:"enabled"`
			AllowSFTP bool   `json:"allow_sftp"`
			CreatedAt int64  `json:"created_at"`
			UpdatedAt int64  `json:"updated_at"`
		}
		out := make([]item, 0, len(users))
		for _, u := range users {
			out = append(out, item{
				ID:        u.ID,
				Username:  u.Username,
				RootPath:  u.RootPath,
				Enabled:   u.Enabled,
				AllowSFTP: u.AllowSFTP,
				CreatedAt: u.CreatedAt,
				UpdatedAt: u.UpdatedAt,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
	case http.MethodPost:
		var req struct {
			Username  string `json:"username"`
			Password  string `json:"password"`
			RootPath  string `json:"root_path"`
			AllowSFTP bool   `json:"allow_sftp"`
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
		id, err := s.DB.CreateUser(r.Context(), req.Username, h, root, req.AllowSFTP)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "create user failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

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
				RootPath  string `json:"root_path"`
				Enabled   bool   `json:"enabled"`
				AllowSFTP bool   `json:"allow_sftp"`
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
			if err := s.DB.UpdateUser(r.Context(), userID, root, req.Enabled, req.AllowSFTP); err != nil {
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

type ctxKey string

const (
	ctxUserID   ctxKey = "user_id"
	ctxUserRoot ctxKey = "user_root"
)

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

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
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

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
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

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	root := r.Context().Value(ctxUserRoot).(string)
	path := r.URL.Query().Get("path")
	local, err := fsutil.ResolveWithinRoot(root, path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	st, err := os.Stat(local)
	if err != nil || st.IsDir() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	name := filepath.Base(local)
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("content-disposition", "attachment; filename=\""+escapeQuotes(name)+"\"")
	http.ServeFile(w, r, local)
}

func readMultipartFile(r *http.Request, field string) (multipart.File, *multipart.FileHeader, error) {
	if err := r.ParseMultipartForm(128 << 20); err != nil {
		return nil, nil, err
	}
	return r.FormFile(field)
}

func escapeQuotes(s string) string {
	return strings.ReplaceAll(s, "\"", "")
}

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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

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
