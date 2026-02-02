package httpapi

import (
	"sync"
	"time"
)

// bucket tracks request counts for a single key within a window.
type bucket struct {
	count   int
	resetAt time.Time
}

// fixedWindowLimiter enforces a simple fixed-window rate limit.
type fixedWindowLimiter struct {
	mu      sync.Mutex
	win     time.Duration
	max     int
	buckets map[string]*bucket
	stopCh  chan struct{}
}

// newFixedWindowLimiter creates a limiter and starts its cleanup loop.
func newFixedWindowLimiter(max int, window time.Duration) *fixedWindowLimiter {
	l := &fixedWindowLimiter{
		win:     window,
		max:     max,
		buckets: make(map[string]*bucket),
		stopCh:  make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Allow records a hit and reports whether the key is still allowed.
// When denied, it returns the remaining time until reset.
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

// cleanupLoop periodically removes expired buckets to limit memory use.
func (l *fixedWindowLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-l.stopCh:
			return
		}
	}
}

// cleanup deletes buckets whose window has expired.
func (l *fixedWindowLimiter) cleanup() {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if now.After(b.resetAt) {
			delete(l.buckets, key)
		}
	}
}

// Stop halts the background cleanup loop.
func (l *fixedWindowLimiter) Stop() {
	close(l.stopCh)
}
