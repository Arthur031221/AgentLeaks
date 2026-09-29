// Command agentleaks finds, redacts and blocks API keys in the local history
// of AI coding tools.
package main

import (
	"os"

	"github.com/Arthur031221/agentleaks/internal/cli"
)

// version is overridden at release time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
