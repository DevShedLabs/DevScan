package inspectors

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type GoModInspector struct{}

func (i *GoModInspector) Name() string      { return "gomod" }
func (i *GoModInspector) Ecosystem() string { return "go" }

func (i *GoModInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return nil, nil
	}

	// Global go binaries aren't enumerable with versions — skip.
	if scope == "global" {
		return nil, nil
	}

	gomodPath, err := safeJoin(path, "go.mod")
	if err != nil {
		return nil, err
	}
	if path != "" {
		if _, err := os.Stat(gomodPath); err != nil {
			return nil, nil
		}
	}

	// Parse go.mod directly to determine which deps are direct vs indirect.
	directDeps := parseDirectDeps(gomodPath)

	cmd := exec.Command("go", "list", "-m", "-json", "all")
	if path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	// go list -json emits concatenated JSON objects, not an array.
	var packages []schema.Package
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var mod struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Main    bool   `json:"Main"`
		}
		if err := dec.Decode(&mod); err != nil {
			break
		}
		if mod.Main || mod.Version == "" {
			continue
		}
		packages = append(packages, schema.Package{
			Name:      mod.Path,
			Version:   mod.Version,
			Ecosystem: "go",
			Scope:     "project",
			Direct:    directDeps[mod.Path],
			Path:      gomodPath,
		})
	}

	return packages, nil
}

// parseDirectDeps reads go.mod and returns a set of module paths that are
// direct dependencies (i.e. not marked with the "// indirect" comment).
func parseDirectDeps(gomodPath string) map[string]bool {
	direct := map[string]bool{}
	f, err := os.Open(gomodPath)
	if err != nil {
		return direct
	}
	defer f.Close()

	inRequire := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		// Single-line require outside a block: "require module/path vX.Y.Z"
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			line = strings.TrimSpace(line)
			inRequire = false // single-line, not a block
			if !strings.Contains(line, "// indirect") {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					direct[parts[0]] = true
				}
			}
			continue
		}
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			if !strings.Contains(line, "// indirect") {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					direct[parts[0]] = true
				}
			}
		}
	}
	return direct
}
