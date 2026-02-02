package httpapi

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(sr, r)

		dur := time.Since(start)
		ip := clientIP(r)
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sr.status,
			"bytes", sr.bytes,
			"remote_ip", ip,
			"duration_ms", dur.Milliseconds(),
		}
		if r.URL.RawQuery != "" {
			attrs = append(attrs, "query", r.URL.RawQuery)
		}
		lvl := levelForStatus(sr.status)
		s.Logger.Log(r.Context(), lvl, "http request", attrs...)
	})
}

func levelForStatus(code int) slog.Level {
	if code >= 500 {
		return slog.LevelError
	}
	if code >= 400 {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

func retryAfterSeconds(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	return strconv.Itoa(int(d.Seconds()))
}
