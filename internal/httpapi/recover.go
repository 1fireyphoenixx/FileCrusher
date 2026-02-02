package httpapi

import (
	"net/http"
	"runtime/debug"
)

// withRecover guards handlers against panics and returns a 500 response.
func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.Logger.Error("panic", "panic", v, "stack", string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
