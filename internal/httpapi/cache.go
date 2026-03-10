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
func (s *Server) putCachedSession(token string, sess *db.Session, user *db.User) {
	s.sessionMu.Lock()
	s.sessionCache[token] = &cachedSession{
		session:   sess,
		user:      user,
		fetchedAt: time.Now(),
	}
	s.sessionMu.Unlock()
}

// evictSession removes a token from the session cache.
func (s *Server) evictSession(token string) {
	s.sessionMu.Lock()
	delete(s.sessionCache, token)
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
