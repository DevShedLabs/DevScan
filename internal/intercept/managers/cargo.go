package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Cargo struct{}

func (c *Cargo) Name() string       { return "cargo" }
func (c *Cargo) Binaries() []string { return []string{"cargo"} }

func (c *Cargo) FindReal(shimsDir string) (string, error) {
	return findReal("cargo", shimsDir)
}

// cargo add pkg@1.0 / cargo install pkg --version 1.0
var cargoInstallSubcmds = map[string]bool{
	"add":     true,
	"install": true,
}

func (c *Cargo) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}
	if !cargoInstallSubcmds[args[0]] {
		return nil, ModePassthrough, nil
	}

	var pkgs []Pkg
	skipNext := false
	explicitVersion := ""

	for i, arg := range args[1:] {
		_ = i
		if skipNext {
			skipNext = false
			continue
		}
		// --version / -V consume the next token as the version spec.
		if arg == "--version" || arg == "-V" {
			if i+2 < len(args) {
				explicitVersion = args[i+2]
			}
			skipNext = true
			continue
		}
		if strings.HasPrefix(arg, "--version=") {
			explicitVersion = strings.TrimPrefix(arg, "--version=")
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, version := cargoSplitNameVersion(arg)
		if version == "" {
			version = explicitVersion
		}
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	if len(pkgs) == 0 {
		return nil, ModePassthrough, nil
	}
	return pkgs, ModeExplicit, nil
}

// cargoSplitNameVersion handles "pkg" and "pkg@1.0.0"
func cargoSplitNameVersion(arg string) (string, string) {
	idx := strings.Index(arg, "@")
	if idx < 0 {
		return arg, ""
	}
	return arg[:idx], arg[idx+1:]
}

func (c *Cargo) ResolveVersion(name string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "devscan-intercept")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crates.io returned %d", resp.StatusCode)
	}
	var data struct {
		Crate struct {
			NewestVersion string `json:"newest_version"`
		} `json:"crate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Crate.NewestVersion, nil
}
