package managers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type GoMod struct{}

func (g *GoMod) Name() string       { return "go" }
func (g *GoMod) Binaries() []string { return []string{"go"} }

func (g *GoMod) FindReal(shimsDir string) (string, error) {
	return findReal("go", shimsDir)
}

// go get and go install fetch packages; everything else is passthrough.
var goInstallSubcmds = map[string]bool{
	"get":     true,
	"install": true,
}

func (g *GoMod) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	if len(args) == 0 {
		return nil, ModePassthrough, nil
	}
	if !goInstallSubcmds[args[0]] {
		return nil, ModePassthrough, nil
	}

	var pkgs []Pkg
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// go get module@version or module@latest
		name, version := goSplitNameVersion(arg)
		if version == "latest" {
			version = ""
		}
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	if len(pkgs) == 0 {
		return nil, ModePassthrough, nil
	}
	return pkgs, ModeExplicit, nil
}

// goSplitNameVersion handles "module/path@v1.2.3" and "module/path"
func goSplitNameVersion(arg string) (string, string) {
	idx := strings.LastIndex(arg, "@")
	if idx < 0 {
		return arg, ""
	}
	version := strings.TrimPrefix(arg[idx+1:], "v")
	return arg[:idx], version
}

func (g *GoMod) ResolveVersion(name string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", name)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("go proxy returned %d", resp.StatusCode)
	}
	var data struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return strings.TrimPrefix(data.Version, "v"), nil
}
