package inspectors

import (
	"encoding/json"
	"os/exec"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type GoModInspector struct{}

func (i *GoModInspector) Name() string      { return "gomod" }
func (i *GoModInspector) Ecosystem() string { return "go" }

func (i *GoModInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return nil, nil
	}

	// Global installed binaries: `go env GOPATH` + /bin — not easily enumerable with versions.
	// For project scope: `go list -m -json all` gives module graph with versions.
	if scope == "global" {
		return nil, nil
	}

	cmd := exec.Command("go", "list", "-m", "-json", "all")
	if path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	// go list -json outputs concatenated JSON objects, not an array.
	var packages []schema.Package
	dec := json.NewDecoder(jsonStream(out))
	first := true
	for dec.More() {
		var mod struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Main    bool   `json:"Main"`
		}
		if err := dec.Decode(&mod); err != nil {
			break
		}
		// Skip the main module itself and indirect deps without versions.
		if mod.Main || mod.Version == "" || first {
			first = false
			continue
		}
		packages = append(packages, schema.Package{
			Name:      mod.Path,
			Version:   mod.Version,
			Ecosystem: "go",
			Scope:     "project",
			Direct:    true,
		})
	}

	return packages, nil
}

// jsonStream wraps a byte slice so the JSON decoder can handle concatenated objects.
type jsonStreamReader struct {
	data []byte
	pos  int
}

func (r *jsonStreamReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, nil
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func jsonStream(data []byte) *jsonStreamReader {
	return &jsonStreamReader{data: data}
}
