package httpapi

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiterConcurrentRequests(t *testing.T) {
	l := newFixedWindowLimiter(10, time.Minute)
	t.Cleanup(l.Stop)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Allow("shared-client"); ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 10 {
		t.Fatalf("accepted %d concurrent requests, want 10", got)
	}
	if ok, wait := l.Allow("shared-client"); ok || wait <= 0 {
		t.Fatalf("exhausted bucket: allowed=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("another-client"); !ok {
		t.Fatal("one client exhausted another client's limit")
	}
	// Advance the bucket deadline without a timing-dependent sleep.
	l.mu.Lock()
	l.buckets["shared-client"].resetAt = time.Now().Add(-time.Second)
	l.mu.Unlock()
	if ok, _ := l.Allow("shared-client"); !ok {
		t.Fatal("expired window did not reset")
	}
}
