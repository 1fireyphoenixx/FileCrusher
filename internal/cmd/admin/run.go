package admin

import (
	"flag"
	"fmt"

	"filecrusher/internal/adminapi"
	"filecrusher/internal/adminui"
	"filecrusher/internal/logging"
	"filecrusher/internal/version"
	tea "github.com/charmbracelet/bubbletea"
)

type Options struct {
	Addr        string
	TLSInsecure bool
}

func Run(args []string) error {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	var opt Options
	var showVersion bool
	var logLevel string
	fs.StringVar(&opt.Addr, "addr", "https://127.0.0.1:5132", "server address")
	fs.BoolVar(&opt.TLSInsecure, "insecure", false, "skip TLS verification (recommended only for localhost/self-signed)")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.StringVar(&logLevel, "log-level", "error", "log level: debug|info|warning|error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Printf("filecrusher admin %s\n", version.Version)
		return nil
	}
	_, _, _ = logging.New(logging.Options{Level: logLevel, DefaultSlog: true})

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
