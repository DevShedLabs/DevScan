package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Pip struct{}

func (p *Pip) Name() string       { return "pip" }
func (p *Pip) Binaries() []string { return []string{"pip", "pip3"} }

func (p *Pip) FindReal(shimsDir string) (string, error) {
	return findReal("pip3", shimsDir)
}

var pipInstallSubcmds = map[string]bool{
	"install": true,
}

func (p *Pip) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}
	if !pipInstallSubcmds[args[0]] {
		return nil, ModePassthrough, nil
	}

	var pkgs []Pkg
	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		// Flags that consume the next argument.
		if arg == "-r" || arg == "--requirement" ||
			arg == "-t" || arg == "--target" ||
			arg == "-i" || arg == "--index-url" ||
			arg == "-c" || arg == "--constraint" {
			// -r requirements.txt installs from file — lockfile mode.
			if arg == "-r" || arg == "--requirement" {
				return nil, ModeLockfile, nil
			}
			skipNext = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, version := pipSplitNameVersion(arg)
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	if len(pkgs) == 0 {
		return nil, ModeLockfile, nil
	}
	return pkgs, ModeExplicit, nil
}

// pipSplitNameVersion handles: pkg, pkg==1.0, pkg>=1.0, pkg~=1.0
func pipSplitNameVersion(arg string) (string, string) {
	for _, op := range []string{"==", ">=", "<=", "~=", "!=", ">"} {
		if idx := strings.Index(arg, op); idx >= 0 {
			return arg[:idx], arg[idx+len(op):]
		}
	}
	return arg, ""
}

func (p *Pip) ResolveVersion(name string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pypi returned %d", resp.StatusCode)
	}
	var data struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Info.Version, nil
}
