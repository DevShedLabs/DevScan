package inspectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type CargoInspector struct{}

func (i *CargoInspector) Name() string      { return "cargo" }
func (i *CargoInspector) Ecosystem() string { return "crates.io" }

func (i *CargoInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if _, err := exec.LookPath("cargo"); err != nil {
		return nil, nil
	}
	if scope == "global" {
		return i.inspectGlobal()
	}
	return i.inspectProject(path)
}

func (i *CargoInspector) inspectGlobal() ([]schema.Package, error) {
	out, err := exec.Command("cargo", "install", "--list").Output()
	if err != nil {
		return nil, nil
	}

	cargoHome := os.Getenv("CARGO_HOME")
	if cargoHome == "" {
		home, _ := os.UserHomeDir()
		cargoHome = filepath.Join(home, ".cargo")
	}
	binDir := filepath.Join(cargoHome, "bin")

	// Output format:
	//   ripgrep v14.1.0:
	//       rg
	//   pac-cli v0.1.0 (/Users/jeffrey/www/PAC/crates/pac-cli):
	//       pac
	var packages []schema.Package
	for _, line := range splitLines(string(out)) {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, version, localPath := parseCargoListLine(line)
		if name == "" {
			continue
		}

		pkgPath := localPath
		if pkgPath == "" {
			pkgPath = filepath.Join(binDir, name)
		}

		packages = append(packages, schema.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "crates.io",
			Scope:     "global",
			Direct:    true,
			Path:      pkgPath,
		})
	}
	return packages, nil
}

func (i *CargoInspector) inspectProject(path string) ([]schema.Package, error) {
	cmd := exec.Command("cargo", "metadata", "--format-version=1", "--no-deps")
	if path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var meta struct {
		Packages []struct {
			Name         string `json:"name"`
			Version      string `json:"version"`
			Source       string `json:"source"`
			ManifestPath string `json:"manifest_path"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(out, &meta); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(meta.Packages))
	for _, p := range meta.Packages {
		if p.Source == "" {
			continue
		}
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "crates.io",
			Scope:     "project",
			Direct:    true,
			Path:      filepath.Dir(p.ManifestPath),
		})
	}
	return packages, nil
}

// parseCargoListLine parses a line like:
//
//	ripgrep v14.1.0:
//	pac-cli v0.1.0 (/Users/jeffrey/www/PAC/crates/pac-cli):
func parseCargoListLine(line string) (name, version, localPath string) {
	// Strip trailing colon
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")

	// Extract optional local path in parens at the end
	if idx := strings.LastIndex(line, " ("); idx != -1 {
		localPath = strings.Trim(line[idx+2:], "()")
		line = strings.TrimSpace(line[:idx])
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", ""
	}
	name = parts[0]
	version = strings.TrimPrefix(parts[1], "v")
	return name, version, localPath
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}
