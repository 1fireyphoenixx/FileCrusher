// Command filecrusher is the main entry point for the CLI binary.
// It dispatches to subcommands like setup, server, admin, and reset-admin.
package main

import (
	"fmt"
	"os"

	"filecrusher/internal/cmd/admin"
	"filecrusher/internal/cmd/resetadmin"
	"filecrusher/internal/cmd/server"
	"filecrusher/internal/cmd/setup"
)

// main is the process entry point and forwards to run for testable logic.
func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

// run parses argv and invokes the matching subcommand handler.
// It returns an error for missing or unknown subcommands.
func run(argv []string) error {
	if len(argv) < 2 {
		usage()
		return fmt.Errorf("missing subcommand")
	}

	switch argv[1] {
	case "setup":
		return setup.Run(argv[2:])
	case "reset-admin":
		return resetadmin.Run(argv[2:])
	case "server":
		return server.Run(argv[2:])
	case "admin":
		return admin.Run(argv[2:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand: %s", argv[1])
	}
}

// usage prints the canonical CLI syntax to stderr.
func usage() {
	fmt.Fprintln(os.Stderr, "filecrusher <setup|reset-admin|server|admin> [flags]")
}
