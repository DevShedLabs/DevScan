package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/intercept"
	"github.com/spf13/cobra"
)

const module = "github.com/DevShedLabs/devscan"

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update devscan to the latest release",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Updating devscan...")

		// Clear the module download cache for this module so Go resolves
		// @latest from the origin rather than from a stale cached tag list.
		if err := clearModuleCache(); err != nil {
			// Non-fatal: warn and continue — go install may still pick up the new version.
			fmt.Fprintf(os.Stderr, "warning: could not clear module cache: %v\n", err)
		}

		env := append(os.Environ(),
			"GOPROXY=direct",
			"GONOSUMDB=*",
		)
		c := exec.Command("go", "install", module+"@latest")
		c.Env = env
		out, err := c.CombinedOutput()
		if err != nil {
			return fmt.Errorf("update failed: %w\n%s", err, string(out))
		}
		if err := intercept.EnsureShims(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not update intercept shims: %v\n", err)
		}
		fmt.Println("Done. Run `devscan --version` to confirm.")
		return nil
	},
}

// clearModuleCache removes the cached download entries for this module so
// that go install @latest resolves the tag list fresh from the origin.
// It targets only this module's subdirectory under GOMODCACHE — it does not
// wipe the entire module cache.
func clearModuleCache() error {
	gomodcache, err := goEnv("GOMODCACHE")
	if err != nil {
		return err
	}

	// The module cache stores paths with capital letters escaped as !lower,
	// e.g. github.com/DevShedLabs → github.com/!dev!shed!labs
	escaped := escapeModPath(module)
	cacheDir := filepath.Join(gomodcache, "cache", "download", filepath.FromSlash(escaped), "@v")

	entries, err := filepath.Glob(filepath.Join(cacheDir, "*.info"))
	if err != nil {
		return err
	}
	// Also remove .lock, .ziphash, list files so the resolver starts clean.
	for _, pattern := range []string{"*.info", "*.mod", "*.zip", "*.ziphash", "list"} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, pattern))
		entries = append(entries, matches...)
	}

	for _, f := range entries {
		_ = os.Remove(f)
	}
	return nil
}

func goEnv(name string) (string, error) {
	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// escapeModPath converts a module path to the case-encoded form used by the
// Go module cache: each uppercase letter X becomes !x.
func escapeModPath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 32) // to lowercase
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
