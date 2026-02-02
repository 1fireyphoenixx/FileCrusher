// Package httpapi exposes the HTTPS API and handlers.
package httpapi

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"filecrusher/internal/db"
)

// clientIP extracts the remote IP without a port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// isLoopback reports whether a string is a loopback IP.
func isLoopback(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// parseCIDRorIP parses either a CIDR string or a single IP address.
func parseCIDRorIP(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, errors.New("invalid ip")
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
		ip = ip.To4()
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// isAdminAllowedByIP checks the admin allowlist against the caller IP.
func isAdminAllowedByIP(d *db.DB, r *http.Request) (bool, error) {
	// Default: allow loopback only unless allowlist has entries.
	entries, err := d.ListAdminIPAllowlist(r.Context())
	if err != nil {
		return false, err
	}
	ipStr := clientIP(r)
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false, nil
	}
	if len(entries) == 0 {
		return ip.IsLoopback(), nil
	}
	for _, e := range entries {
		n, err := parseCIDRorIP(e.CIDR)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}
