package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Bun struct{}

func (b *Bun) Name() string       { return "bun" }
func (b *Bun) Binaries() []string { return []string{"bun"} }

func (b *Bun) FindReal(shimsDir string) (string, error) {
	return findReal("bun", shimsDir)
}

// Bun uses the same npm registry, so version resolution is identical.
var bunInstallSubcmds = map[string]bool{
	"install": true,
	"i":       true,
	"add":     true,
	"a":       true,
}

var bunLockfileSubcmds = map[string]bool{
	"install": true, // `bun install` with no args reads bun.lockb
}

func (b *Bun) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}
	sub := args[0]
	if !bunInstallSubcmds[sub] {
		return nil, ModePassthrough, nil
	}

	var pkgs []Pkg
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, version := splitNameVersion(arg) // reuse npm's splitter (same format)
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	// `bun install` with no extra args installs from lockfile.
	if len(pkgs) == 0 {
		return nil, ModeLockfile, nil
	}
	return pkgs, ModeExplicit, nil
}

func (b *Bun) ResolveVersion(name string) (string, error) {
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
