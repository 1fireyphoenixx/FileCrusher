// Package adminapi provides an HTTP client for the admin API.
package adminapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// API path constants to avoid string duplication.
const (
	apiAdminUsersPath = "/api/admin/users"
)

// Client wraps HTTP calls to the admin API and manages cookies.
type Client struct {
	baseURL *url.URL
	hc      *http.Client
}

// ClientOptions configures the admin API client.
type ClientOptions struct {
	Addr      string
	Insecure  bool
	Timeout   time.Duration
	UserAgent string
}

// NewClient builds a client with optional TLS and timeout settings.
func NewClient(opt ClientOptions) (*Client, error) {
	if opt.Addr == "" {
		return nil, errors.New("addr is required")
	}
	u, err := url.Parse(opt.Addr)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if !strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http") {
		return nil, errors.New("invalid scheme")
	}
	if u.User != nil {
		return nil, errors.New("userinfo not allowed")
	}
	if u.Host == "" {
		return nil, errors.New("invalid addr")
	}

	jar, _ := cookiejar.New(nil)
	t := &http.Transport{}
	if strings.EqualFold(u.Scheme, "https") {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: opt.Insecure} //nolint:gosec
	}

	timeout := opt.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}

	hc := &http.Client{Transport: t, Jar: jar, Timeout: timeout}
	return &Client{baseURL: u, hc: hc}, nil
}

// LoginAdmin authenticates and stores the admin session cookie.
func (c *Client) LoginAdmin(password string) error {
	var req struct {
		Password string `json:"password"`
	}
	req.Password = password
	return c.doJSON("POST", "/api/admin/login", req, nil)
}

// LogoutAdmin clears the admin session cookie.
func (c *Client) LogoutAdmin() error {
	return c.doJSON("POST", "/api/admin/logout", map[string]string{}, nil)
}

// User mirrors the admin API user representation.
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	RootPath    string `json:"root_path"`
	Enabled     bool   `json:"enabled"`
	AllowSFTP   bool   `json:"allow_sftp"`
	AllowFTP    bool   `json:"allow_ftp"`
	AllowFTPS   bool   `json:"allow_ftps"`
	AllowSCP    bool   `json:"allow_scp"`
	AllowWebDAV bool   `json:"allow_webdav"`
}

// ListUsers retrieves all users.
func (c *Client) ListUsers() ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := c.doJSON("GET", apiAdminUsersPath, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// CreateUser creates a new user and returns its ID.
func (c *Client) CreateUser(username, password, rootPath string, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV bool) (int64, error) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		RootPath    string `json:"root_path"`
		AllowSFTP   bool   `json:"allow_sftp"`
		AllowFTP    bool   `json:"allow_ftp"`
		AllowFTPS   bool   `json:"allow_ftps"`
		AllowSCP    bool   `json:"allow_scp"`
		AllowWebDAV bool   `json:"allow_webdav"`
	}
	req.Username = username
	req.Password = password
	req.RootPath = rootPath
	req.AllowSFTP = allowSFTP
	req.AllowFTP = allowFTP
	req.AllowFTPS = allowFTPS
	req.AllowSCP = allowSCP
	req.AllowWebDAV = allowWebDAV

	var resp struct {
		ID int64 `json:"id"`
	}
	if err := c.doJSON("POST", apiAdminUsersPath, req, &resp); err != nil {
		return 0, err
	}
	return resp.ID, nil
}

// UpdateUser updates a user's properties and permissions.
func (c *Client) UpdateUser(id int64, rootPath string, enabled, allowSFTP, allowFTP, allowFTPS, allowSCP, allowWebDAV bool) error {
	var req struct {
		RootPath    string `json:"root_path"`
		Enabled     bool   `json:"enabled"`
		AllowSFTP   bool   `json:"allow_sftp"`
		AllowFTP    bool   `json:"allow_ftp"`
		AllowFTPS   bool   `json:"allow_ftps"`
		AllowSCP    bool   `json:"allow_scp"`
		AllowWebDAV bool   `json:"allow_webdav"`
	}
	req.RootPath = rootPath
	req.Enabled = enabled
	req.AllowSFTP = allowSFTP
	req.AllowFTP = allowFTP
	req.AllowFTPS = allowFTPS
	req.AllowSCP = allowSCP
	req.AllowWebDAV = allowWebDAV
	return c.doJSON("PUT", apiAdminUsersPath+"/"+itoa(id), req, nil)
}

// DeleteUser removes a user by ID.
func (c *Client) DeleteUser(id int64) error {
	return c.doJSON("DELETE", apiAdminUsersPath+"/"+itoa(id), nil, nil)
}

// SetUserPassword updates a user's password.
func (c *Client) SetUserPassword(id int64, password string) error {
	var req struct {
		Password string `json:"password"`
	}
	req.Password = password
	return c.doJSON("POST", apiAdminUsersPath+"/"+itoa(id)+"/password", req, nil)
}

// SSHKey mirrors the admin API SSH key representation.
type SSHKey struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	CreatedAt   int64  `json:"created_at"`
}

// AdminIPAllowEntry mirrors the admin IP allowlist representation.
type AdminIPAllowEntry struct {
	ID        int64  `json:"id"`
	CIDR      string `json:"cidr"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
}

// ListAdminIPAllowlist retrieves admin IP allowlist entries.
func (c *Client) ListAdminIPAllowlist() ([]AdminIPAllowEntry, error) {
	var resp struct {
		Entries []AdminIPAllowEntry `json:"entries"`
	}
	if err := c.doJSON("GET", "/api/admin/ip-allowlist", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Entries, nil
}

// AddAdminIPAllowlist adds a new admin allowlist entry.
func (c *Client) AddAdminIPAllowlist(cidr, note string) (int64, string, error) {
	var req struct {
		CIDR string `json:"cidr"`
		Note string `json:"note"`
	}
	req.CIDR = cidr
	req.Note = note
	var resp struct {
		ID   int64  `json:"id"`
		CIDR string `json:"cidr"`
	}
	if err := c.doJSON("POST", "/api/admin/ip-allowlist", req, &resp); err != nil {
		return 0, "", err
	}
	return resp.ID, resp.CIDR, nil
}

// DeleteAdminIPAllowlist removes an allowlist entry by ID.
func (c *Client) DeleteAdminIPAllowlist(id int64) error {
	return c.doJSON("DELETE", "/api/admin/ip-allowlist/"+itoa(id), nil, nil)
}

// ListKeys returns SSH keys for a user.
func (c *Client) ListKeys(userID int64) ([]SSHKey, error) {
	var resp struct {
		Keys []SSHKey `json:"keys"`
	}
	if err := c.doJSON("GET", apiAdminUsersPath+"/"+itoa(userID)+"/keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// AddKey adds an SSH key for a user and returns its ID and fingerprint.
func (c *Client) AddKey(userID int64, publicKey, comment string) (int64, string, error) {
	var req struct {
		PublicKey string `json:"public_key"`
		Comment   string `json:"comment"`
	}
	req.PublicKey = publicKey
	req.Comment = comment

	var resp struct {
		ID          int64  `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := c.doJSON("POST", apiAdminUsersPath+"/"+itoa(userID)+"/keys", req, &resp); err != nil {
		return 0, "", err
	}
	return resp.ID, resp.Fingerprint, nil
}

// DeleteKey removes an SSH key for a user.
func (c *Client) DeleteKey(userID, keyID int64) error {
	return c.doJSON("DELETE", apiAdminUsersPath+"/"+itoa(userID)+"/keys/"+itoa(keyID), nil, nil)
}

// doJSON executes an HTTP request and decodes JSON responses.
func (c *Client) doJSON(method, path string, body any, out any) error {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	}
	u := c.baseURL.ResolveReference(&url.URL{Path: path})
	if u.Scheme != c.baseURL.Scheme || u.Host != c.baseURL.Host {
		return errors.New("refusing to change request host")
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	req.Header.Set("accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&er)
		if er.Error != "" {
			return errors.New(er.Error)
		}
		return errors.New(resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// itoa converts an int64 to string for URL paths.
func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
