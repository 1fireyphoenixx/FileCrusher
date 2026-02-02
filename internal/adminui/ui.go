// Package adminui implements the interactive admin TUI using Bubble Tea.
package adminui

import (
	"fmt"
	"net/url"
	"strings"

	"filecrusher/internal/adminapi"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// state represents the current screen in the admin UI.
type state int

const (
	stateLogin state = iota
	stateUsers
	stateNewUser
	stateEditUser
	stateSetPassword
	stateKeys
	stateAllowlist
)

// Model holds all UI state for the admin TUI.
type Model struct {
	client *adminapi.Client
	addr   string

	st  state
	err string

	pass textinput.Model

	users   []adminapi.User
	userLst list.Model

	newUsername    textinput.Model
	newPassword    textinput.Model
	newRoot        textinput.Model
	newAllowSFTP   bool
	newAllowFTP    bool
	newAllowFTPS   bool
	newAllowSCP    bool
	newAllowWebDAV bool

	edRoot        textinput.Model
	edEn          bool
	edAllowSFTP   bool
	edAllowFTP    bool
	edAllowFTPS   bool
	edAllowSCP    bool
	edAllowWebDAV bool

	setPw textinput.Model

	keys       []adminapi.SSHKey
	keyLst     list.Model
	addKey     textinput.Model
	addComment textinput.Model

	allowEntries []adminapi.AdminIPAllowEntry
	allowLst     list.Model
	allowCIDR    textinput.Model
	allowNote    textinput.Model
}

// New constructs a UI model and initializes inputs and lists.
func New(client *adminapi.Client, addr string) Model {
	pass := textinput.New()
	pass.Placeholder = "Admin password"
	pass.EchoMode = textinput.EchoPassword
	pass.Focus()
	pass.Prompt = "Password: "

	lst := list.New(nil, list.NewDefaultDelegate(), 0, 0)
	lst.Title = "Users"

	keyLst := list.New(nil, list.NewDefaultDelegate(), 0, 0)
	keyLst.Title = "SSH Keys"

	allowLst := list.New(nil, list.NewDefaultDelegate(), 0, 0)
	allowLst.Title = "Admin IP allowlist"

	m := Model{client: client, st: stateLogin, pass: pass, userLst: lst, keyLst: keyLst, allowLst: allowLst}
	m.addr = redactAddr(addr)

	m.newUsername = textinput.New()
	m.newUsername.Placeholder = "username"
	m.newUsername.Prompt = "Username: "
	m.newPassword = textinput.New()
	m.newPassword.Placeholder = "password"
	m.newPassword.EchoMode = textinput.EchoPassword
	m.newPassword.Prompt = "Password: "
	m.newRoot = textinput.New()
	m.newRoot.Placeholder = "/absolute/path"
	m.newRoot.Prompt = "Root: "

	m.edRoot = textinput.New()
	m.edRoot.Placeholder = "/absolute/path"
	m.edRoot.Prompt = "Root: "

	m.setPw = textinput.New()
	m.setPw.Placeholder = "new password"
	m.setPw.EchoMode = textinput.EchoPassword
	m.setPw.Prompt = "New password: "

	m.addKey = textinput.New()
	m.addKey.Placeholder = "ssh-ed25519 AAAA..."
	m.addKey.Prompt = "Public key: "
	m.addComment = textinput.New()
	m.addComment.Placeholder = "optional"
	m.addComment.Prompt = "Comment: "

	m.allowCIDR = textinput.New()
	m.allowCIDR.Placeholder = "127.0.0.1 or 10.0.0.0/8"
	m.allowCIDR.Prompt = "CIDR/IP: "
	m.allowNote = textinput.New()
	m.allowNote.Placeholder = "optional"
	m.allowNote.Prompt = "Note: "

	return m
}

// Init returns the initial command for the Bubble Tea runtime.
func (m Model) Init() tea.Cmd {
	return nil
}

type errMsg string
type usersMsg []adminapi.User
type keysMsg []adminapi.SSHKey
type allowMsg []adminapi.AdminIPAllowEntry
type okMsg struct{}

// Update routes messages based on UI state.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.userLst.SetSize(msg.Width-4, msg.Height-8)
		m.keyLst.SetSize(msg.Width-4, msg.Height-10)
		m.allowLst.SetSize(msg.Width-4, msg.Height-12)
		return m, nil
	case errMsg:
		m.err = string(msg)
		return m, nil
	case usersMsg:
		m.users = []adminapi.User(msg)
		items := make([]list.Item, 0, len(m.users))
		for _, u := range m.users {
			items = append(items, userItem(u))
		}
		m.userLst.SetItems(items)
		m.err = ""
		return m, nil
	case keysMsg:
		m.keys = []adminapi.SSHKey(msg)
		items := make([]list.Item, 0, len(m.keys))
		for _, k := range m.keys {
			items = append(items, keyItem(k))
		}
		m.keyLst.SetItems(items)
		m.err = ""
		return m, nil
	case allowMsg:
		m.allowEntries = []adminapi.AdminIPAllowEntry(msg)
		items := make([]list.Item, 0, len(m.allowEntries))
		for _, e := range m.allowEntries {
			items = append(items, allowItem(e))
		}
		m.allowLst.SetItems(items)
		m.err = ""
		return m, nil
	case okMsg:
		m.err = ""
		if m.st == stateLogin {
			m.st = stateUsers
			return m, refreshUsersCmd(m.client)
		}
		return m, nil
	}

	switch m.st {
	case stateLogin:
		var cmd tea.Cmd
		m.pass, cmd = m.pass.Update(msg)
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "enter":
				pw := m.pass.Value()
				m.pass.SetValue("")
				return m, tea.Batch(cmd, loginCmd(m.client, pw))
			case "ctrl+c", "q":
				return m, tea.Quit
			}
		}
		return m, cmd

	case stateUsers:
		var cmd tea.Cmd
		m.userLst, cmd = m.userLst.Update(msg)
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "r":
				return m, refreshUsersCmd(m.client)
			case "n":
				m.st = stateNewUser
				m.err = ""
				m.newUsername.SetValue("")
				m.newPassword.SetValue("")
				m.newRoot.SetValue("")
				m.newAllowSFTP = true
				m.newAllowFTP = false
				m.newAllowFTPS = false
				m.newAllowSCP = false
				m.newAllowWebDAV = false
				m.newUsername.Focus()
				return m, nil
			case "e":
				u, ok := m.selectedUser()
				if !ok {
					return m, nil
				}
				m.st = stateEditUser
				m.err = ""
				m.edRoot.SetValue(u.RootPath)
				m.edEn = u.Enabled
				m.edAllowSFTP = u.AllowSFTP
				m.edAllowFTP = u.AllowFTP
				m.edAllowFTPS = u.AllowFTPS
				m.edAllowSCP = u.AllowSCP
				m.edAllowWebDAV = u.AllowWebDAV
				m.edRoot.Focus()
				return m, nil
			case "d":
				u, ok := m.selectedUser()
				if !ok {
					return m, nil
				}
				return m, tea.Batch(deleteUserCmd(m.client, u.ID), refreshUsersCmd(m.client))
			case "p":
				_, ok := m.selectedUser()
				if !ok {
					return m, nil
				}
				m.st = stateSetPassword
				m.err = ""
				m.setPw.SetValue("")
				m.setPw.Focus()
				return m, nil
			case "k":
				u, ok := m.selectedUser()
				if !ok {
					return m, nil
				}
				m.st = stateKeys
				m.err = ""
				m.addKey.SetValue("")
				m.addComment.SetValue("")
				m.addKey.Focus()
				return m, refreshKeysCmd(m.client, u.ID)
			case "w":
				m.st = stateAllowlist
				m.err = ""
				m.allowCIDR.SetValue("")
				m.allowNote.SetValue("")
				m.allowCIDR.Focus()
				return m, refreshAllowlistCmd(m.client)
			}
		}
		return m, cmd

	case stateNewUser:
		return m.updateNewUser(msg)
	case stateEditUser:
		return m.updateEditUser(msg)
	case stateSetPassword:
		return m.updateSetPassword(msg)
	case stateKeys:
		return m.updateKeys(msg)
	case stateAllowlist:
		return m.updateAllowlist(msg)
	default:
		return m, nil
	}
}

// View renders the current screen as a string.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString("FileCrusher admin")
	if m.addr != "" {
		b.WriteString(" (" + m.addr + ")")
	}
	b.WriteString("\n\n")

	switch m.st {
	case stateLogin:
		b.WriteString("Login\n")
		b.WriteString(m.pass.View())
		b.WriteString("\n\n")
		b.WriteString("Enter to login. q to quit.\n")
	case stateUsers:
		b.WriteString(m.userLst.View())
		b.WriteString("\n")
		b.WriteString("Keys: n=new e=edit d=delete p=set-pass k=keys w=allowlist r=refresh q=quit\n")
	case stateNewUser:
		b.WriteString("Create user\n\n")
		b.WriteString(m.newUsername.View() + "\n")
		b.WriteString(m.newPassword.View() + "\n")
		b.WriteString(m.newRoot.View() + "\n")
		b.WriteString(fmt.Sprintf("Allow SFTP:   %v (toggle with alt+s)\n", m.newAllowSFTP))
		b.WriteString(fmt.Sprintf("Allow FTP:    %v (toggle with alt+f)\n", m.newAllowFTP))
		b.WriteString(fmt.Sprintf("Allow FTPS:   %v (toggle with alt+t)\n", m.newAllowFTPS))
		b.WriteString(fmt.Sprintf("Allow SCP:    %v (toggle with alt+c)\n", m.newAllowSCP))
		b.WriteString(fmt.Sprintf("Allow WebDAV: %v (toggle with alt+w)\n\n", m.newAllowWebDAV))
		b.WriteString("Enter=save  esc=back\n")
	case stateEditUser:
		u, ok := m.selectedUser()
		if ok {
			b.WriteString("Edit user: " + u.Username + "\n\n")
		}
		b.WriteString(m.edRoot.View() + "\n")
		b.WriteString(fmt.Sprintf("Enabled: %v (toggle with e)\n", m.edEn))
		b.WriteString(fmt.Sprintf("Allow SFTP:   %v (toggle with alt+s)\n", m.edAllowSFTP))
		b.WriteString(fmt.Sprintf("Allow FTP:    %v (toggle with alt+f)\n", m.edAllowFTP))
		b.WriteString(fmt.Sprintf("Allow FTPS:   %v (toggle with alt+t)\n", m.edAllowFTPS))
		b.WriteString(fmt.Sprintf("Allow SCP:    %v (toggle with alt+c)\n", m.edAllowSCP))
		b.WriteString(fmt.Sprintf("Allow WebDAV: %v (toggle with alt+w)\n\n", m.edAllowWebDAV))
		b.WriteString("Enter=save  esc=back\n")
	case stateSetPassword:
		u, ok := m.selectedUser()
		if ok {
			b.WriteString("Set password for: " + u.Username + "\n\n")
		}
		b.WriteString(m.setPw.View())
		b.WriteString("\n\nEnter=save  esc=back\n")
	case stateKeys:
		u, ok := m.selectedUser()
		if ok {
			b.WriteString("SSH keys for: " + u.Username + "\n\n")
		}
		b.WriteString(m.keyLst.View())
		b.WriteString("\nAdd key\n")
		b.WriteString(m.addKey.View() + "\n")
		b.WriteString(m.addComment.View() + "\n")
		b.WriteString("\nEnter=add key  d=delete selected key  esc=back\n")
	case stateAllowlist:
		b.WriteString("Admin IP allowlist\n\n")
		b.WriteString(m.allowLst.View())
		b.WriteString("\nAdd entry\n")
		b.WriteString(m.allowCIDR.View() + "\n")
		b.WriteString(m.allowNote.View() + "\n")
		b.WriteString("\nalt+a=add  alt+d=delete selected  esc=back\n")
	}

	if m.err != "" {
		b.WriteString("\nError: " + m.err + "\n")
	}

	return b.String()
}

type userItem adminapi.User

func (u userItem) Title() string { return u.Username }
func (u userItem) Description() string {
	return fmt.Sprintf(
		"root=%s enabled=%v sftp=%v ftp=%v ftps=%v scp=%v webdav=%v",
		u.RootPath,
		u.Enabled,
		u.AllowSFTP,
		u.AllowFTP,
		u.AllowFTPS,
		u.AllowSCP,
		u.AllowWebDAV,
	)
}
func (u userItem) FilterValue() string { return u.Username }

type keyItem adminapi.SSHKey

func (k keyItem) Title() string       { return k.Fingerprint }
func (k keyItem) Description() string { return k.Comment }
func (k keyItem) FilterValue() string { return k.Fingerprint }

type allowItem adminapi.AdminIPAllowEntry

func (a allowItem) Title() string       { return a.CIDR }
func (a allowItem) Description() string { return a.Note }
func (a allowItem) FilterValue() string { return a.CIDR }

// selectedUser returns the currently highlighted user list entry.
func (m *Model) selectedUser() (adminapi.User, bool) {
	if m.userLst.SelectedItem() == nil {
		return adminapi.User{}, false
	}
	if it, ok := m.userLst.SelectedItem().(userItem); ok {
		return adminapi.User(it), true
	}
	return adminapi.User{}, false
}

func loginCmd(c *adminapi.Client, password string) tea.Cmd {
	return func() tea.Msg {
		if err := c.LoginAdmin(password); err != nil {
			return errMsg(err.Error())
		}
		return okMsg{}
	}
}

func refreshUsersCmd(c *adminapi.Client) tea.Cmd {
	return func() tea.Msg {
		users, err := c.ListUsers()
		if err != nil {
			return errMsg(err.Error())
		}
		return usersMsg(users)
	}
}

func deleteUserCmd(c *adminapi.Client, id int64) tea.Cmd {
	return func() tea.Msg {
		if err := c.DeleteUser(id); err != nil {
			return errMsg(err.Error())
		}
		return okMsg{}
	}
}

func refreshKeysCmd(c *adminapi.Client, userID int64) tea.Cmd {
	return func() tea.Msg {
		keys, err := c.ListKeys(userID)
		if err != nil {
			return errMsg(err.Error())
		}
		return keysMsg(keys)
	}
}

func refreshAllowlistCmd(c *adminapi.Client) tea.Cmd {
	return func() tea.Msg {
		entries, err := c.ListAdminIPAllowlist()
		if err != nil {
			return errMsg(err.Error())
		}
		return allowMsg(entries)
	}
}

func addAllowCmd(c *adminapi.Client, cidr, note string) tea.Cmd {
	return func() tea.Msg {
		_, _, err := c.AddAdminIPAllowlist(cidr, note)
		if err != nil {
			return errMsg(err.Error())
		}
		return okMsg{}
	}
}

func delAllowCmd(c *adminapi.Client, id int64) tea.Cmd {
	return func() tea.Msg {
		if err := c.DeleteAdminIPAllowlist(id); err != nil {
			return errMsg(err.Error())
		}
		return okMsg{}
	}
}

func addKeyCmd(c *adminapi.Client, userID int64, pub, comment string) tea.Cmd {
	return func() tea.Msg {
		_, _, err := c.AddKey(userID, pub, comment)
		if err != nil {
			return errMsg(err.Error())
		}
		return okMsg{}
	}
}

func deleteKeyCmd(c *adminapi.Client, userID, keyID int64) tea.Cmd {
	return func() tea.Msg {
		if err := c.DeleteKey(userID, keyID); err != nil {
			return errMsg(err.Error())
		}
		return okMsg{}
	}
}

// updateNewUser handles input while creating a new user.
func (m Model) updateNewUser(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.st = stateUsers
			return m, refreshUsersCmd(m.client)
		case "alt+s":
			m.newAllowSFTP = !m.newAllowSFTP
			return m, nil
		case "alt+f":
			m.newAllowFTP = !m.newAllowFTP
			return m, nil
		case "alt+t":
			m.newAllowFTPS = !m.newAllowFTPS
			return m, nil
		case "alt+c":
			m.newAllowSCP = !m.newAllowSCP
			return m, nil
		case "alt+w":
			m.newAllowWebDAV = !m.newAllowWebDAV
			return m, nil
		case "enter":
			idCmd := func() tea.Cmd {
				return func() tea.Msg {
					_, err := m.client.CreateUser(
						m.newUsername.Value(),
						m.newPassword.Value(),
						m.newRoot.Value(),
						m.newAllowSFTP,
						m.newAllowFTP,
						m.newAllowFTPS,
						m.newAllowSCP,
						m.newAllowWebDAV,
					)
					if err != nil {
						return errMsg(err.Error())
					}
					return okMsg{}
				}
			}()
			m.st = stateUsers
			return m, tea.Batch(idCmd, refreshUsersCmd(m.client))
		}
	}

	// Focus order: username -> password -> root
	var cmd tea.Cmd
	if m.newUsername.Focused() {
		m.newUsername, cmd = m.newUsername.Update(msg)
		if km, ok := msg.(tea.KeyMsg); ok && km.String() == "tab" {
			m.newUsername.Blur()
			m.newPassword.Focus()
		}
		return m, cmd
	}
	if m.newPassword.Focused() {
		m.newPassword, cmd = m.newPassword.Update(msg)
		if km, ok := msg.(tea.KeyMsg); ok && km.String() == "tab" {
			m.newPassword.Blur()
			m.newRoot.Focus()
		}
		return m, cmd
	}
	m.newRoot, cmd = m.newRoot.Update(msg)
	return m, cmd
}

// updateEditUser handles input while editing a user.
func (m Model) updateEditUser(msg tea.Msg) (tea.Model, tea.Cmd) {
	u, ok := m.selectedUser()
	if !ok {
		m.st = stateUsers
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.st = stateUsers
			return m, refreshUsersCmd(m.client)
		case "e":
			m.edEn = !m.edEn
			return m, nil
		case "alt+s":
			m.edAllowSFTP = !m.edAllowSFTP
			return m, nil
		case "alt+f":
			m.edAllowFTP = !m.edAllowFTP
			return m, nil
		case "alt+t":
			m.edAllowFTPS = !m.edAllowFTPS
			return m, nil
		case "alt+c":
			m.edAllowSCP = !m.edAllowSCP
			return m, nil
		case "alt+w":
			m.edAllowWebDAV = !m.edAllowWebDAV
			return m, nil
		case "enter":
			cmd := func() tea.Cmd {
				return func() tea.Msg {
					if err := m.client.UpdateUser(u.ID, m.edRoot.Value(), m.edEn, m.edAllowSFTP, m.edAllowFTP, m.edAllowFTPS, m.edAllowSCP, m.edAllowWebDAV); err != nil {
						return errMsg(err.Error())
					}
					return okMsg{}
				}
			}()
			m.st = stateUsers
			return m, tea.Batch(cmd, refreshUsersCmd(m.client))
		}
	}
	var cmd tea.Cmd
	m.edRoot, cmd = m.edRoot.Update(msg)
	return m, cmd
}

// updateSetPassword handles input while setting a user password.
func (m Model) updateSetPassword(msg tea.Msg) (tea.Model, tea.Cmd) {
	u, ok := m.selectedUser()
	if !ok {
		m.st = stateUsers
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.st = stateUsers
			return m, nil
		case "enter":
			cmd := func() tea.Cmd {
				return func() tea.Msg {
					if err := m.client.SetUserPassword(u.ID, m.setPw.Value()); err != nil {
						return errMsg(err.Error())
					}
					return okMsg{}
				}
			}()
			m.st = stateUsers
			return m, tea.Batch(cmd, refreshUsersCmd(m.client))
		}
	}
	var cmd tea.Cmd
	m.setPw, cmd = m.setPw.Update(msg)
	return m, cmd
}

// updateKeys handles input on the SSH keys screen.
func (m Model) updateKeys(msg tea.Msg) (tea.Model, tea.Cmd) {
	u, ok := m.selectedUser()
	if !ok {
		m.st = stateUsers
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.st = stateUsers
			return m, nil
		case "enter":
			pub := strings.TrimSpace(m.addKey.Value())
			com := strings.TrimSpace(m.addComment.Value())
			m.addKey.SetValue("")
			m.addComment.SetValue("")
			return m, tea.Batch(addKeyCmd(m.client, u.ID, pub, com), refreshKeysCmd(m.client, u.ID))
		case "d":
			if m.keyLst.SelectedItem() == nil {
				return m, nil
			}
			if it, ok := m.keyLst.SelectedItem().(keyItem); ok {
				k := adminapi.SSHKey(it)
				return m, tea.Batch(deleteKeyCmd(m.client, u.ID, k.ID), refreshKeysCmd(m.client, u.ID))
			}
		}
	}

	var cmd tea.Cmd
	if m.addKey.Focused() {
		m.addKey, cmd = m.addKey.Update(msg)
		if km, ok := msg.(tea.KeyMsg); ok && km.String() == "tab" {
			m.addKey.Blur()
			m.addComment.Focus()
		}
		return m, cmd
	}
	if m.addComment.Focused() {
		m.addComment, cmd = m.addComment.Update(msg)
		if km, ok := msg.(tea.KeyMsg); ok && km.String() == "tab" {
			m.addComment.Blur()
		}
		return m, cmd
	}
	m.keyLst, cmd = m.keyLst.Update(msg)
	return m, cmd
}

// updateAllowlist handles input on the admin allowlist screen.
func (m Model) updateAllowlist(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.st = stateUsers
			return m, nil
		case "alt+a":
			cidr := strings.TrimSpace(m.allowCIDR.Value())
			note := strings.TrimSpace(m.allowNote.Value())
			m.allowCIDR.SetValue("")
			m.allowNote.SetValue("")
			m.allowCIDR.Focus()
			return m, tea.Batch(addAllowCmd(m.client, cidr, note), refreshAllowlistCmd(m.client))
		case "alt+d":
			if m.allowLst.SelectedItem() == nil {
				return m, nil
			}
			if it, ok := m.allowLst.SelectedItem().(allowItem); ok {
				e := adminapi.AdminIPAllowEntry(it)
				return m, tea.Batch(delAllowCmd(m.client, e.ID), refreshAllowlistCmd(m.client))
			}
		}
	}

	var cmd tea.Cmd
	if m.allowCIDR.Focused() {
		m.allowCIDR, cmd = m.allowCIDR.Update(msg)
		if km, ok := msg.(tea.KeyMsg); ok && km.String() == "tab" {
			m.allowCIDR.Blur()
			m.allowNote.Focus()
		}
		return m, cmd
	}
	if m.allowNote.Focused() {
		m.allowNote, cmd = m.allowNote.Update(msg)
		if km, ok := msg.(tea.KeyMsg); ok && km.String() == "tab" {
			m.allowNote.Blur()
		}
		return m, cmd
	}
	m.allowLst, cmd = m.allowLst.Update(msg)
	return m, cmd
}

func redactAddr(addr string) string {
	u, err := url.Parse(addr)
	if err != nil {
		return ""
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	return u.Scheme + "://" + u.Host
}

func RequireInsecureByDefault(addr string) bool {
	u, err := url.Parse(addr)
	if err != nil {
		return true
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
