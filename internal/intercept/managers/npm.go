package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type NPM struct{}

func (n *NPM) Name() string      { return "npm" }
func (n *NPM) Binaries() []string { return []string{"npm"} }

func (n *NPM) FindReal(shimsDir string) (string, error) {
	return findReal("npm", shimsDir)
}

// installSubcmds are npm subcommands that install packages.
var installSubcmds = map[string]bool{
	"install": true,
	"i":       true,
	"add":     true,
	"isntall": true, // npm's own typo alias
}

// lockfileSubcmds are npm subcommands that install from a lockfile.
var lockfileSubcmds = map[string]bool{
	"ci":          true,
	"clean-install": true,
}

func (n *NPM) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}

	sub := args[0]

	if lockfileSubcmds[sub] {
		return nil, ModeLockfile, nil
	}

	if !installSubcmds[sub] {
		return nil, ModePassthrough, nil
	}

	// Collect non-flag arguments after the subcommand.
	var pkgs []Pkg
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Scoped packages: @scope/name@version or @scope/name
		// Unscoped: name@version or name
		name, version := splitNameVersion(arg)
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	// `npm install` with no args installs from package.json — treat as lockfile mode.
	if len(pkgs) == 0 {
		return nil, ModeLockfile, nil
	}

	return pkgs, ModeExplicit, nil
}

// splitNameVersion splits "pkg@1.2.3" → ("pkg", "1.2.3").
// Handles scoped packages: "@scope/pkg@1.2.3" → ("@scope/pkg", "1.2.3").
func splitNameVersion(arg string) (string, string) {
	// Scoped package: starts with @
	if strings.HasPrefix(arg, "@") {
		// Find the @ that separates name from version (after the scope slash).
		rest := arg[1:] // strip leading @
		slashIdx := strings.Index(rest, "/")
		if slashIdx < 0 {
			return arg, ""
		}
		afterSlash := rest[slashIdx+1:]
		atIdx := strings.Index(afterSlash, "@")
		if atIdx < 0 {
			return arg, ""
		}
		name := "@" + rest[:slashIdx+1+atIdx]
		version := afterSlash[atIdx+1:]
		return name, version
	}

	// Unscoped package.
	idx := strings.Index(arg, "@")
	if idx < 0 {
		return arg, ""
	}
	return arg[:idx], arg[idx+1:]
}

func (n *NPM) ResolveVersion(name string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://registry.npmjs.org/%s/latest", name)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	var data struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Version, nil
}

// findReal locates the real binary by searching PATH entries, skipping shimsDir.
func findReal(binary, shimsDir string) (string, error) {
	pathEnv := os.Getenv("PATH")
	dirs := filepath.SplitList(pathEnv)

	shimsDir = filepath.Clean(shimsDir)

	for _, dir := range dirs {
		if filepath.Clean(dir) == shimsDir {
			continue
		}
		candidate := filepath.Join(dir, binary)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}

	// Last resort: ask the shell with shimsDir stripped from PATH.
	// This handles version managers (nvm, pyenv, asdf) that inject their own
	// shims outside the directories we already walked above.
	filteredPath := filterPath(pathEnv, shimsDir)
	cmd := exec.Command("which", binary)
	cmd.Env = append(os.Environ(), "PATH="+filteredPath)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("could not find real %s binary", binary)
	}
	real := strings.TrimSpace(string(out))
	if real == "" || filepath.Clean(filepath.Dir(real)) == shimsDir {
		return "", fmt.Errorf("could not find real %s binary (only found our own shim)", binary)
	}
	return real, nil
}

// filterPath returns the PATH string with shimsDir removed.
func filterPath(pathEnv, shimsDir string) string {
	shimsDir = filepath.Clean(shimsDir)
	var kept []string
	for _, dir := range filepath.SplitList(pathEnv) {
		if filepath.Clean(dir) != shimsDir {
			kept = append(kept, dir)
		}
	}
	return strings.Join(kept, string(os.PathListSeparator))
}
