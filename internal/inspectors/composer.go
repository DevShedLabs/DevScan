package inspectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type ComposerInspector struct{}

func (i *ComposerInspector) Name() string      { return "composer" }
func (i *ComposerInspector) Ecosystem() string { return "packagist" }

func (i *ComposerInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if _, err := exec.LookPath("composer"); err != nil {
		return nil, nil
	}

	if scope == "project" {
		if path == "" {
			return nil, nil
		}
		if _, err := os.Stat(filepath.Join(path, "composer.json")); err != nil {
			return nil, nil
		}
	}

	// --path adds install paths; --format=json for machine-readable output.
	args := []string{"show", "--path", "--format=json", "--no-interaction"}
	if scope == "global" {
		args = append(args, "--global")
	}

	cmd := exec.Command("composer", args...)
	if scope == "project" && path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		if len(out) == 0 {
			return nil, nil
		}
	}

	var raw struct {
		Installed []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Path    string `json:"path"`
		} `json:"installed"`
	}

	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(raw.Installed))
	for _, p := range raw.Installed {
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "packagist",
			Scope:     scope,
			Direct:    true,
			Path:      p.Path,
		})
	}
	return packages, nil
}
