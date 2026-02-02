package admin

import (
	"flag"

	"filecrusher/internal/adminapi"
	"filecrusher/internal/adminui"
	tea "github.com/charmbracelet/bubbletea"
)

type Options struct {
	Addr        string
	TLSInsecure bool
}

func Run(args []string) error {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	var opt Options
	fs.StringVar(&opt.Addr, "addr", "https://127.0.0.1:5132", "server address")
	fs.BoolVar(&opt.TLSInsecure, "insecure", false, "skip TLS verification (recommended only for localhost/self-signed)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	insecure := opt.TLSInsecure
	if !opt.TLSInsecure {
		insecure = adminui.RequireInsecureByDefault(opt.Addr)
	}
	if !insecure && adminui.RequireInsecureByDefault(opt.Addr) {
		// Not reachable (guard), but keep for clarity.
		insecure = true
	}

	c, err := adminapi.NewClient(adminapi.ClientOptions{Addr: opt.Addr, Insecure: insecure})
	if err != nil {
		return err
	}

	p := tea.NewProgram(adminui.New(c, opt.Addr), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}
