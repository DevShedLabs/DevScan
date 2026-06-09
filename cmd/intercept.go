package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/DevShedLabs/devscan/internal/intercept"
	"github.com/spf13/cobra"
)

var interceptCmd = &cobra.Command{
	Use:   "intercept",
	Short: "Manage package manager shims for real-time supply-chain protection",
	Long: `Intercept wraps npm, pip, cargo, and bun with shims that check every
explicit package install against your compiled blocklist before it runs.

If a package is flagged, the install is blocked before any code executes —
before post-install hooks can run.

Shims are symlinks from ~/.devscan/shims/<manager> to the devscan binary.
devscan update keeps shims current automatically.`,
}

var interceptEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Install shims and patch shell profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := intercept.Enable(); err != nil {
			return err
		}
		shimsDir, _ := intercept.ShimsDir()
		fmt.Println("Intercept enabled.")
		fmt.Println()
		fmt.Printf("  Shims written to: %s\n", shimsDir)
		fmt.Println()
		fmt.Println("  Reload your shell to activate:")
		fmt.Println("    source ~/.zshrc   # zsh")
		fmt.Println("    source ~/.bashrc  # bash")
		fmt.Println()
		fmt.Println("  Or start a new terminal session.")
		return nil
	},
}

var interceptDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Remove shims and clean shell profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := intercept.Disable(); err != nil {
			return err
		}
		fmt.Println("Intercept disabled. Reload your shell to deactivate.")
		return nil
	},
}

var interceptStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show which shims are active",
	RunE: func(cmd *cobra.Command, args []string) error {
		statuses, err := intercept.Status()
		if err != nil {
			return err
		}

		fmt.Println("Intercept shim status:")
		fmt.Println()
		for _, s := range statuses {
			mark := "✗"
			label := "inactive"
			if s.Active {
				mark = "✓"
				label = "active"
			}
			fmt.Printf("  %s  %-6s  %s  (%s)\n", mark, s.Binary, label, s.Path)
		}
		fmt.Println()

		shimsDir, _ := intercept.ShimsDir()
		inPath := isInPath(shimsDir)
		if inPath {
			fmt.Println("  ~/.devscan/shims is on PATH ✓")
		} else {
			fmt.Println("  ~/.devscan/shims is NOT on PATH — run `devscan intercept enable` or reload your shell")
		}
		return nil
	},
}

func isInPath(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p == dir {
			return true
		}
	}
	return false
}

func init() {
	interceptCmd.AddCommand(interceptEnableCmd)
	interceptCmd.AddCommand(interceptDisableCmd)
	interceptCmd.AddCommand(interceptStatusCmd)
	rootCmd.AddCommand(interceptCmd)
}
