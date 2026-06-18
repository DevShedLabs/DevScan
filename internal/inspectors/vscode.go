package inspectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

// VSCodeInspector enumerates extensions installed in VSCode, VSCode Insiders,
// Cursor, and Codium. Extensions from all detected installs are merged and
// deduplicated by publisher.name@version.
//
// Two sources are read per install:
//   - extensions.json  — the registry VSCode maintains; fast, always present
//   - extensions/<dir>/package.json — fallback for non-gallery (vsix) installs
//     or when extensions.json is absent
type VSCodeInspector struct{}

func (v *VSCodeInspector) Name() string      { return "vscode" }
func (v *VSCodeInspector) Ecosystem() string { return "vscode" }

// vscodeVariant describes one VSCode-family installation.
type vscodeVariant struct {
	label    string // human name used in Path field
	extDir   func(home string) string
}

var vscodeVariants = []vscodeVariant{
	{"vscode", func(home string) string { return filepath.Join(home, ".vscode", "extensions") }},
	{"vscode-insiders", func(home string) string { return filepath.Join(home, ".vscode-insiders", "extensions") }},
	{"cursor", func(home string) string { return filepath.Join(home, ".cursor", "extensions") }},
	{"codium", func(home string) string { return filepath.Join(home, ".vscode-oss", "extensions") }},
}

func (v *VSCodeInspector) Inspect(scope, path string) ([]schema.Package, error) {
	// VSCode extensions are always global; project scope has no meaning here.
	if scope != "global" {
		return nil, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	seen := map[string]bool{}
	var packages []schema.Package

	for _, variant := range vscodeVariants {
		extDir := variant.extDir(home)
		if _, err := os.Stat(extDir); err != nil {
			continue // this variant is not installed
		}

		pkgs := readVSCodeExtensions(extDir, variant.label)
		for _, p := range pkgs {
			key := p.Name + "@" + p.Version
			if !seen[key] {
				seen[key] = true
				packages = append(packages, p)
			}
		}
	}

	return packages, nil
}

// readVSCodeExtensions reads all extensions from a single VSCode extensions directory.
// It first tries extensions.json (the registry), then falls back to walking
// the directory and reading individual package.json files.
func readVSCodeExtensions(extDir, label string) []schema.Package {
	if pkgs, ok := readExtensionsJSON(extDir, label); ok {
		return pkgs
	}
	return walkExtensionDirs(extDir, label)
}

// extensionsEntry mirrors the shape of each entry in VSCode's extensions.json.
type extensionsEntry struct {
	Identifier struct {
		ID string `json:"id"`
	} `json:"identifier"`
	Version          string `json:"version"`
	RelativeLocation string `json:"relativeLocation"`
	Metadata         struct {
		IsBuiltin bool   `json:"isBuiltin"`
		Source    string `json:"source"` // "gallery" | "vsix" | ""
	} `json:"metadata"`
}

func readExtensionsJSON(extDir, label string) ([]schema.Package, bool) {
	data, err := os.ReadFile(filepath.Join(extDir, "extensions.json"))
	if err != nil {
		return nil, false
	}

	var entries []extensionsEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, false
	}

	var pkgs []schema.Package
	for _, e := range entries {
		if e.Metadata.IsBuiltin {
			continue
		}
		id := strings.ToLower(e.Identifier.ID)
		if id == "" || e.Version == "" {
			continue
		}
		pkgs = append(pkgs, schema.Package{
			Name:      id,
			Version:   e.Version,
			Ecosystem: "vscode",
			Scope:     "global",
			Direct:    true,
			Path:      filepath.Join(extDir, e.RelativeLocation),
		})
	}
	return pkgs, true
}

// walkExtensionDirs is the fallback: read package.json from each
// subdirectory when extensions.json is absent or unreadable.
func walkExtensionDirs(extDir, label string) []schema.Package {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return nil
	}

	var pkgs []schema.Package
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pkgJSON := filepath.Join(extDir, entry.Name(), "package.json")
		data, err := os.ReadFile(pkgJSON)
		if err != nil {
			continue
		}

		var manifest struct {
			Publisher string `json:"publisher"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			continue
		}
		if manifest.Publisher == "" || manifest.Name == "" || manifest.Version == "" {
			continue
		}

		id := strings.ToLower(manifest.Publisher + "." + manifest.Name)
		pkgs = append(pkgs, schema.Package{
			Name:      id,
			Version:   manifest.Version,
			Ecosystem: "vscode",
			Scope:     "global",
			Direct:    true,
			Path:      filepath.Join(extDir, entry.Name()),
		})
	}
	return pkgs
}
