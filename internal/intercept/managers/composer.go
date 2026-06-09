package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Composer struct{}

func (c *Composer) Name() string       { return "composer" }
func (c *Composer) Binaries() []string { return []string{"composer"} }

func (c *Composer) FindReal(shimsDir string) (string, error) {
	return findReal("composer", shimsDir)
}

var composerInstallSubcmds = map[string]bool{
	"require": true,
}

var composerLockfileSubcmds = map[string]bool{
	"install": true,
	"update":  true,
}

func (c *Composer) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}
	sub := args[0]

	if composerLockfileSubcmds[sub] {
		return nil, ModeLockfile, nil
	}
	if !composerInstallSubcmds[sub] {
		return nil, ModePassthrough, nil
	}

	// composer require vendor/pkg:^1.0 vendor/other:~2.0
	var pkgs []Pkg
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, version := composerSplitNameVersion(arg)
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	if len(pkgs) == 0 {
		return nil, ModeLockfile, nil
	}
	return pkgs, ModeExplicit, nil
}

// composerSplitNameVersion handles "vendor/pkg", "vendor/pkg:^1.0", "vendor/pkg:1.0.0"
func composerSplitNameVersion(arg string) (string, string) {
	idx := strings.Index(arg, ":")
	if idx < 0 {
		return arg, ""
	}
	version := arg[idx+1:]
	// Strip constraint operators so we have a bare version for the blocklist check.
	version = strings.TrimLeft(version, "^~>=<!")
	return arg[:idx], version
}

func (c *Composer) ResolveVersion(name string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	// Packagist API: /packages/<vendor>/<name>.json
	url := fmt.Sprintf("https://packagist.org/packages/%s.json", name)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("packagist returned %d", resp.StatusCode)
	}
	var data struct {
		Package struct {
			Versions map[string]json.RawMessage `json:"versions"`
		} `json:"package"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	// Return the first non-dev version key (Packagist orders newest first).
	for v := range data.Package.Versions {
		if !strings.HasPrefix(v, "dev-") {
			return strings.TrimPrefix(v, "v"), nil
		}
	}
	return "", fmt.Errorf("no stable version found for %s", name)
}
