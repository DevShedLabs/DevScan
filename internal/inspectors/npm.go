package inspectors

import (
	"encoding/json"
	"os/exec"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type NpmInspector struct{}

func (i *NpmInspector) Name() string      { return "npm" }
func (i *NpmInspector) Ecosystem() string { return "npm" }

func (i *NpmInspector) Inspect(scope, path string) ([]schema.Package, error) {
	args := []string{"list", "--json", "--depth=0"}
	if scope == "global" {
		args = append(args, "--global")
	}

	cmd := exec.Command("npm", args...)
	if scope == "project" && path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		// npm list exits non-zero when packages have issues; still parse output
		if len(out) == 0 {
			return nil, err
		}
	}

	var raw struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	var packages []schema.Package
	for name, dep := range raw.Dependencies {
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
			Scope:     scope,
			Direct:    true,
		})
	}
	return packages, nil
}
