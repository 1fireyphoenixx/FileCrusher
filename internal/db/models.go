// Package db defines persistence models for FileCrusher.
package db

// User represents an account with protocol permissions and storage root.
type User struct {
	ID          int64
	Username    string
	PassHash    string
	RootPath    string
	Enabled     bool
	AllowSFTP   bool
	AllowFTP    bool
	AllowFTPS   bool
	AllowSCP    bool
	AllowWebDAV bool
	CreatedAt   int64
	UpdatedAt   int64
}

// SSHKey stores a user's authorized SSH public key.
type SSHKey struct {
	ID          int64
	UserID      int64
	PublicKey   string
	Fingerprint string
	Comment     string
	CreatedAt   int64
}

// Session represents an authentication session for admin or user access.
type Session struct {
	Token     string
	Kind      string
	SubjectID int64
	CreatedAt int64
	ExpiresAt int64
}

// AdminIPAllowEntry records allowed admin IP/CIDR entries.
type AdminIPAllowEntry struct {
	ID        int64
	CIDR      string
	Note      string
	CreatedAt int64
}
