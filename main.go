package main

import (
	"os"
	"path/filepath"

	"github.com/DevShedLabs/devscan/cmd"
	"github.com/DevShedLabs/devscan/internal/intercept"
)

func main() {
	// When the binary is invoked via a shim symlink (e.g. ~/.devscan/shims/npm),
	// argv[0] is the package manager name — run shim logic instead of the CLI.
	if name := filepath.Base(os.Args[0]); intercept.IsShimName(name) {
		intercept.RunShim(name, os.Args[1:])
		return
	}
	cmd.Execute()
}
