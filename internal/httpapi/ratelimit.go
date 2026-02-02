package httpapi

import (
	"sync"
	"time"
)

type bucket struct {
	count   int
	resetAt time.Time
}

// fixedWindowLimiter is a small fixed-window limiter.
// It is intentionally simple and in-memory.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	win     time.Duration
	max     int
	buckets map[string]*bucket
}

func newFixedWindowLimiter(max int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{win: window, max: max, buckets: make(map[string]*bucket)}
}

func (l *fixedWindowLimiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil || now.After(b.resetAt) {
		b = &bucket{count: 0, resetAt: now.Add(l.win)}
		l.buckets[key] = b
	}
	b.count++
	if b.count <= l.max {
		return true, 0
	}
	return false, time.Until(b.resetAt)
}
