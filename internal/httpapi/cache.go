package httpapi

import (
	"context"
	"time"

	"filecrusher/internal/db"
)

const (
	// sessionCacheTTL controls how long session lookups are cached before
	// re-querying the database. Short enough that disabled accounts are
	// locked out within seconds.
	sessionCacheTTL = 30 * time.Second

	// allowlistCacheTTL controls how long the admin IP allowlist is cached.
	// Mutations (add/delete) invalidate immediately; this TTL only governs
	// the periodic background refresh.
	allowlistCacheTTL = 5 * time.Minute

	// maxSessionCacheSize caps the number of cached sessions to prevent
	// unbounded memory growth. When exceeded, the oldest entry is evicted.
	maxSessionCacheSize = 1024
)

// cachedSession holds a looked-up session and its associated user.
type cachedSession struct {
	session   *db.Session
	user      *db.User // nil for admin sessions
	fetchedAt time.Time
}

// initCaches prepares in-memory caches. Must be called once at startup.
func (s *Server) initCaches() {
	s.sessionCache = make(map[string]*cachedSession)
}

// getCachedSession returns a cached session if the TTL has not expired.
func (s *Server) getCachedSession(token string) (*cachedSession, bool) {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	cs, ok := s.sessionCache[token]
	if !ok || time.Since(cs.fetchedAt) > sessionCacheTTL {
		return nil, false
	}
	return cs, true
}

// putCachedSession stores a session lookup result in the cache.
// If the cache exceeds maxSessionCacheSize, the oldest entry is evicted.
func (s *Server) putCachedSession(token string, sess *db.Session, user *db.User) {
	s.sessionMu.Lock()
	s.sessionCache[token] = &cachedSession{
		session:   sess,
		user:      user,
		fetchedAt: time.Now(),
	}
	if len(s.sessionCache) > maxSessionCacheSize {
		s.evictOldestLocked()
	}
	s.sessionMu.Unlock()
}

// evictOldestLocked removes the oldest entry from the session cache.
// Caller must hold s.sessionMu write lock.
func (s *Server) evictOldestLocked() {
	var oldestToken string
	var oldestTime time.Time
	first := true
	for tok, cs := range s.sessionCache {
		if first || cs.fetchedAt.Before(oldestTime) {
			oldestToken = tok
			oldestTime = cs.fetchedAt
			first = false
		}
	}
	if !first {
		delete(s.sessionCache, oldestToken)
	}
}

// evictSession removes a token from the session cache.
func (s *Server) evictSession(token string) {
	s.sessionMu.Lock()
	delete(s.sessionCache, token)
	s.sessionMu.Unlock()
}

// evictSessionsByUserID removes all cached sessions belonging to a given
// user ID. Used when a user is disabled or deleted to ensure the cache
// cannot serve stale grants.
func (s *Server) evictSessionsByUserID(userID int64) {
	s.sessionMu.Lock()
	for tok, cs := range s.sessionCache {
		if cs.session != nil && cs.session.SubjectID == userID {
			delete(s.sessionCache, tok)
		}
	}
	s.sessionMu.Unlock()
}

// cachedAllowlist returns the admin IP allowlist, backed by a TTL cache
// to avoid querying the database on every admin request.
func (s *Server) cachedAllowlist(ctx context.Context) ([]db.AdminIPAllowEntry, error) {
	s.allowlistMu.RLock()
	if time.Now().Before(s.allowlistExpiry) {
		entries := s.allowlistCache
		s.allowlistMu.RUnlock()
		return entries, nil
	}
	s.allowlistMu.RUnlock()

	entries, err := s.DB.ListAdminIPAllowlist(ctx)
	if err != nil {
		return nil, err
	}

	s.allowlistMu.Lock()
	s.allowlistCache = entries
	s.allowlistExpiry = time.Now().Add(allowlistCacheTTL)
	s.allowlistMu.Unlock()

	return entries, nil
}

// invalidateAllowlistCache forces the next allowlist check to re-query the database.
func (s *Server) invalidateAllowlistCache() {
	s.allowlistMu.Lock()
	s.allowlistExpiry = time.Time{}
	s.allowlistMu.Unlock()
}
