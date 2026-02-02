package db

type User struct {
	ID        int64
	Username  string
	PassHash  string
	RootPath  string
	Enabled   bool
	AllowSFTP bool
	AllowFTP  bool
	AllowFTPS bool
	AllowSCP  bool
	CreatedAt int64
	UpdatedAt int64
}

type SSHKey struct {
	ID          int64
	UserID      int64
	PublicKey   string
	Fingerprint string
	Comment     string
	CreatedAt   int64
}

type Session struct {
	Token     string
	Kind      string
	SubjectID int64
	CreatedAt int64
	ExpiresAt int64
}

type AdminIPAllowEntry struct {
	ID        int64
	CIDR      string
	Note      string
	CreatedAt int64
}
