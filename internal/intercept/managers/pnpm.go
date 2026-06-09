package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Pnpm struct{}

func (p *Pnpm) Name() string       { return "pnpm" }
func (p *Pnpm) Binaries() []string { return []string{"pnpm"} }

func (p *Pnpm) FindReal(shimsDir string) (string, error) {
	return findReal("pnpm", shimsDir)
}

var pnpmInstallSubcmds = map[string]bool{
	"install": true,
	"i":       true,
	"add":     true,
}

func (p *Pnpm) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}
	sub := args[0]
	if !pnpmInstallSubcmds[sub] {
		return nil, ModePassthrough, nil
	}

	var pkgs []Pkg
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, version := splitNameVersion(arg) // same format as npm
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	if len(pkgs) == 0 {
		return nil, ModeLockfile, nil
	}
	return pkgs, ModeExplicit, nil
}

func (p *Pnpm) ResolveVersion(name string) (string, error) {
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
