package httpapi

import "strings"

// isRetryableDBErr identifies transient SQLite lock errors.
func isRetryableDBErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	// modernc/sqlite errors are commonly surfaced as strings containing these.
	return strings.Contains(s, "database is locked") ||
		strings.Contains(s, "sqlite_busy") ||
		strings.Contains(s, "busy") ||
		strings.Contains(s, "locked")
}
