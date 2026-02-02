package httpapi

import (
	"sync"
	"time"
)

type bucket struct {
	count   int
	resetAt time.Time
}

type fixedWindowLimiter struct {
	mu      sync.Mutex
	win     time.Duration
	max     int
	buckets map[string]*bucket
	stopCh  chan struct{}
}

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

func (l *fixedWindowLimiter) Stop() {
	close(l.stopCh)
}
