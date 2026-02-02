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

type Client struct {
	baseURL *url.URL
	hc      *http.Client
}

type ClientOptions struct {
	Addr      string
	Insecure  bool
	Timeout   time.Duration
	UserAgent string
}

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

func (c *Client) LoginAdmin(password string) error {
	var req struct {
		Password string `json:"password"`
	}
	req.Password = password
	return c.doJSON("POST", "/api/admin/login", req, nil)
}

func (c *Client) LogoutAdmin() error {
	return c.doJSON("POST", "/api/admin/logout", map[string]string{}, nil)
}

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	RootPath  string `json:"root_path"`
	Enabled   bool   `json:"enabled"`
	AllowSFTP bool   `json:"allow_sftp"`
	AllowFTP  bool   `json:"allow_ftp"`
	AllowFTPS bool   `json:"allow_ftps"`
	AllowSCP  bool   `json:"allow_scp"`
}

func (c *Client) ListUsers() ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := c.doJSON("GET", "/api/admin/users", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

func (c *Client) CreateUser(username, password, rootPath string, allowSFTP, allowFTP, allowFTPS, allowSCP bool) (int64, error) {
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		RootPath  string `json:"root_path"`
		AllowSFTP bool   `json:"allow_sftp"`
		AllowFTP  bool   `json:"allow_ftp"`
		AllowFTPS bool   `json:"allow_ftps"`
		AllowSCP  bool   `json:"allow_scp"`
	}
	req.Username = username
	req.Password = password
	req.RootPath = rootPath
	req.AllowSFTP = allowSFTP
	req.AllowFTP = allowFTP
	req.AllowFTPS = allowFTPS
	req.AllowSCP = allowSCP

	var resp struct {
		ID int64 `json:"id"`
	}
	if err := c.doJSON("POST", "/api/admin/users", req, &resp); err != nil {
		return 0, err
	}
	return resp.ID, nil
}

func (c *Client) UpdateUser(id int64, rootPath string, enabled, allowSFTP, allowFTP, allowFTPS, allowSCP bool) error {
	var req struct {
		RootPath  string `json:"root_path"`
		Enabled   bool   `json:"enabled"`
		AllowSFTP bool   `json:"allow_sftp"`
		AllowFTP  bool   `json:"allow_ftp"`
		AllowFTPS bool   `json:"allow_ftps"`
		AllowSCP  bool   `json:"allow_scp"`
	}
	req.RootPath = rootPath
	req.Enabled = enabled
	req.AllowSFTP = allowSFTP
	req.AllowFTP = allowFTP
	req.AllowFTPS = allowFTPS
	req.AllowSCP = allowSCP
	return c.doJSON("PUT", "/api/admin/users/"+itoa(id), req, nil)
}

func (c *Client) DeleteUser(id int64) error {
	return c.doJSON("DELETE", "/api/admin/users/"+itoa(id), nil, nil)
}

func (c *Client) SetUserPassword(id int64, password string) error {
	var req struct {
		Password string `json:"password"`
	}
	req.Password = password
	return c.doJSON("POST", "/api/admin/users/"+itoa(id)+"/password", req, nil)
}

type SSHKey struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	CreatedAt   int64  `json:"created_at"`
}

type AdminIPAllowEntry struct {
	ID        int64  `json:"id"`
	CIDR      string `json:"cidr"`
	Note      string `json:"note"`
	CreatedAt int64  `json:"created_at"`
}

func (c *Client) ListAdminIPAllowlist() ([]AdminIPAllowEntry, error) {
	var resp struct {
		Entries []AdminIPAllowEntry `json:"entries"`
	}
	if err := c.doJSON("GET", "/api/admin/ip-allowlist", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Entries, nil
}

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

func (c *Client) DeleteAdminIPAllowlist(id int64) error {
	return c.doJSON("DELETE", "/api/admin/ip-allowlist/"+itoa(id), nil, nil)
}

func (c *Client) ListKeys(userID int64) ([]SSHKey, error) {
	var resp struct {
		Keys []SSHKey `json:"keys"`
	}
	if err := c.doJSON("GET", "/api/admin/users/"+itoa(userID)+"/keys", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

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
	if err := c.doJSON("POST", "/api/admin/users/"+itoa(userID)+"/keys", req, &resp); err != nil {
		return 0, "", err
	}
	return resp.ID, resp.Fingerprint, nil
}

func (c *Client) DeleteKey(userID, keyID int64) error {
	return c.doJSON("DELETE", "/api/admin/users/"+itoa(userID)+"/keys/"+itoa(keyID), nil, nil)
}

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

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
