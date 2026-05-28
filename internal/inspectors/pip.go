package inspectors

import (
	"encoding/json"
	"os/exec"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type PipInspector struct{}

func (i *PipInspector) Name() string      { return "pip" }
func (i *PipInspector) Ecosystem() string { return "pypi" }

func (i *PipInspector) Inspect(scope, path string) ([]schema.Package, error) {
	// prefer pip3
	binary := "pip3"
	if _, err := exec.LookPath(binary); err != nil {
		binary = "pip"
		if _, err := exec.LookPath(binary); err != nil {
			return nil, nil
		}
	}

	cmd := exec.Command(binary, "list", "--format=json")
	if scope == "project" && path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var raw []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(raw))
	for _, p := range raw {
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "pypi",
			Scope:     scope,
			Direct:    true,
		})
	}
	return packages, nil
}
