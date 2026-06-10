package inspectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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

	if path != "" {
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err != nil {
			return nil, nil
		}
	}

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
			Dir     string `json:"Dir"` // path in module cache
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
			Direct:    true,
			Path:      mod.Dir,
		})
	}

	return packages, nil
}
