package inspectors

import (
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
	if path == "" {
		return nil, nil
	}
	cargotoml, err := safeJoin(path, "Cargo.toml")
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(cargotoml); err != nil {
		return nil, nil
	}
	return inspectCargoLock(path)
}

// inspectCargoLock parses Cargo.lock for the full resolved dependency tree.
// Cargo.lock is TOML but we can parse it with a simple line scanner since
// the structure is regular: [[package]] sections with name/version/source fields.
func inspectCargoLock(path string) ([]schema.Package, error) {
	lockPath, err := safeJoin(path, "Cargo.lock")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, nil
	}

	var packages []schema.Package
	var curName, curVersion, curSource string

	flush := func() {
		if curName != "" && curVersion != "" && curSource != "" {
			packages = append(packages, schema.Package{
				Name:      curName,
				Version:   curVersion,
				Ecosystem: "crates.io",
				Scope:     "project",
				Direct:    true,
				Path:      lockPath,
			})
		}
		curName, curVersion, curSource = "", "", ""
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "[[package]]" {
			flush()
			continue
		}
		if k, v, ok := parseTomlString(line); ok {
			switch k {
			case "name":
				curName = v
			case "version":
				curVersion = v
			case "source":
				curSource = v
			}
		}
	}
	flush()

	return packages, nil
}

// parseTomlString parses a TOML line of the form: key = "value"
func parseTomlString(line string) (key, value string, ok bool) {
	eq := strings.Index(line, " = ")
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+3:])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		return key, val[1 : len(val)-1], true
	}
	return "", "", false
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
