package inspectors

import (
	"encoding/json"
	"os/exec"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type CargoInspector struct{}

func (i *CargoInspector) Name() string      { return "cargo" }
func (i *CargoInspector) Ecosystem() string { return "crates.io" }

func (i *CargoInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if _, err := exec.LookPath("cargo"); err != nil {
		return nil, nil
	}

	// cargo install --list outputs human-readable text; cargo metadata gives JSON
	// for project mode. For global, we parse `cargo install --list`.
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

	// Output format:
	//   package-name v1.2.3:
	//       binary-name
	var packages []schema.Package
	lines := splitLines(string(out))
	for _, line := range lines {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		// "package-name v1.2.3:"
		var name, version string
		if n, err := parseCargoListLine(line, &name, &version); n == 2 && err == nil {
			packages = append(packages, schema.Package{
				Name:      name,
				Version:   version,
				Ecosystem: "crates.io",
				Scope:     "global",
				Direct:    true,
			})
		}
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
			Name    string `json:"name"`
			Version string `json:"version"`
			Source  string `json:"source"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(out, &meta); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(meta.Packages))
	for _, p := range meta.Packages {
		// Skip workspace-local crates (source is nil for local packages)
		if p.Source == "" {
			continue
		}
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "crates.io",
			Scope:     "project",
			Direct:    true,
		})
	}
	return packages, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func parseCargoListLine(line string, name, version *string) (int, error) {
	// "ripgrep v14.1.0:"  →  name="ripgrep", version="14.1.0"
	var n int
	for i, ch := range line {
		if ch == ' ' {
			*name = line[:i]
			rest := line[i+1:]
			// strip leading 'v' and trailing ':'
			j := len(rest)
			for j > 0 && (rest[j-1] == ':' || rest[j-1] == ' ') {
				j--
			}
			if j > 0 && rest[0] == 'v' {
				*version = rest[1:j]
			} else {
				*version = rest[:j]
			}
			n = 2
			break
		}
	}
	return n, nil
}
