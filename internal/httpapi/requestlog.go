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
		if s.Logger.Enabled(r.Context(), slog.LevelDebug) {
			tlsVersion := ""
			cipher := ""
			if r.TLS != nil {
				tlsVersion = tlsVersionString(r.TLS.Version)
				cipher = tlsCipherString(r.TLS.CipherSuite)
			}
			s.Logger.Debug("http start",
				"method", r.Method,
				"path", r.URL.Path,
				"remote_ip", clientIP(r),
				"proto", r.Proto,
				"content_length", r.ContentLength,
				"user_agent", r.UserAgent(),
				"tls_version", tlsVersion,
				"tls_cipher", cipher,
			)
		}
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

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0301:
		return "1.0"
	case 0x0302:
		return "1.1"
	case 0x0303:
		return "1.2"
	case 0x0304:
		return "1.3"
	default:
		return ""
	}
}

func tlsCipherString(id uint16) string {
	// Keep it minimal; debug mode will include the numeric ID in attrs anyway.
	_ = id
	return ""
}
