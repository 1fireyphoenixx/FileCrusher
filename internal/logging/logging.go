package logging

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
)

func ParseLevel(s string) (slog.Level, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	if s == "" {
		return slog.LevelInfo, nil
	}
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.New("invalid log level")
	}
}

type Options struct {
	Level       string
	AddSource   bool
	JSON        bool
	Writer      io.Writer
	DefaultSlog bool
}

func New(opt Options) (*slog.Logger, slog.Level, error) {
	level, err := ParseLevel(opt.Level)
	if err != nil {
		return nil, 0, err
	}
	var w io.Writer = os.Stderr
	if opt.Writer != nil {
		w = opt.Writer
	}
	if w == nil {
		w = io.Discard
	}
	lo := &slog.HandlerOptions{
		Level:     level,
		AddSource: opt.AddSource || level == slog.LevelDebug,
	}

	var h slog.Handler
	if opt.JSON {
		h = slog.NewJSONHandler(w, lo)
	} else {
		h = slog.NewTextHandler(w, lo)
	}
	lg := slog.New(h)
	if opt.DefaultSlog {
		slog.SetDefault(lg)
	}
	return lg, level, nil
}
