package inspectors

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type PnpmInspector struct{}

func (i *PnpmInspector) Name() string      { return "pnpm" }
func (i *PnpmInspector) Ecosystem() string { return "npm" }

func (i *PnpmInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if scope != "project" || path == "" {
		return nil, nil
	}
	lockPath, err := safeJoin(path, "pnpm-lock.yaml")
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(lockPath); err != nil {
		return nil, nil // not a pnpm project
	}
	return parsePnpmLock(lockPath, path)
}

// parsePnpmLock reads pnpm-lock.yaml and returns all pinned packages.
// Supports lockfile versions 6, 7, 8, and 9.
//
// The packages section contains entries like:
//
//	'lodash@4.17.21':
//	'@scope/name@1.2.3':
func parsePnpmLock(lockPath, projectPath string) ([]schema.Package, error) {
	f, err := os.Open(lockPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	modulesRoot := filepath.Join(projectPath, "node_modules")
	if _, err := os.Stat(modulesRoot); err != nil {
		modulesRoot = ""
	}

	seen := map[string]bool{}
	var packages []schema.Package
	inPackages := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inPackages = false
		}
		if !inPackages {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}
		entry := strings.TrimSuffix(trimmed, ":")
		entry = strings.Trim(entry, "'\"")

		var name, version string
		if strings.HasPrefix(entry, "@") {
			slash := strings.Index(entry, "/")
			if slash < 0 {
				continue
			}
			rest := entry[slash+1:]
			at := strings.LastIndex(rest, "@")
			if at < 0 {
				continue
			}
			name = entry[:slash+1+at]
			version = rest[at+1:]
		} else {
			at := strings.Index(entry, "@")
			if at < 0 {
				continue
			}
			name = entry[:at]
			version = entry[at+1:]
		}

		// Strip peer dep suffix: name@1.0.0(peer@2.0) → 1.0.0
		if idx := strings.Index(version, "("); idx >= 0 {
			version = version[:idx]
		}

		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		pkgPath := ""
		if modulesRoot != "" {
			pkgPath = filepath.Join(modulesRoot, name)
		}

		packages = append(packages, schema.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
			Scope:     "project",
			Direct:    false, // pnpm-lock doesn't distinguish direct vs transitive at this level
			Path:      pkgPath,
		})
	}
	return packages, scanner.Err()
}
