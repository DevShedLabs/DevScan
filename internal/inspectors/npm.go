package inspectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type NpmInspector struct{}

func (i *NpmInspector) Name() string      { return "npm" }
func (i *NpmInspector) Ecosystem() string { return "npm" }

func (i *NpmInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if scope == "project" {
		if path == "" {
			return nil, nil
		}
		pkgjson, err := safeJoin(path, "package.json")
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(pkgjson); err != nil {
			return nil, nil
		}
		return inspectPackageLock(path)
	}

	// Global scope: use npm list
	cmd := exec.Command("npm", "list", "--json", "--depth=0", "--global")
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}

	var raw struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	globalRoot := strings.TrimSpace(func() string {
		o, e := exec.Command("npm", "root", "-g").Output()
		if e != nil {
			return ""
		}
		return string(o)
	}())

	var packages []schema.Package
	for name, dep := range raw.Dependencies {
		pkgPath := ""
		if globalRoot != "" {
			pkgPath = filepath.Join(globalRoot, name)
		}
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
			Scope:     scope,
			Direct:    true,
			Path:      pkgPath,
		})
	}
	return packages, nil
}

// inspectPackageLock reads package-lock.json and returns all resolved packages
// including transitive dependencies, which is where many vulns hide.
func inspectPackageLock(path string) ([]schema.Package, error) {
	// Prefer package-lock.json (npm); fall back to npm list if absent.
	lockPath, err := safeJoin(path, "package-lock.json")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(lockPath)
	if err != nil {
		return inspectNpmList(path)
	}
	defer f.Close()

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: packages map keyed by "node_modules/name" or "node_modules/a/node_modules/b"
		Packages map[string]struct {
			Version              string            `json:"version"`
			Dev                  bool              `json:"dev"`
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		} `json:"packages"`
		// v1: dependencies map keyed by package name
		Dependencies map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev"`
		} `json:"dependencies"`
	}
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, err
	}

	modulesRoot := filepath.Join(path, "node_modules")
	if _, err := os.Stat(modulesRoot); err != nil {
		modulesRoot = ""
	}

	var packages []schema.Package

	if lock.LockfileVersion >= 2 && len(lock.Packages) > 0 {
		// Build reverse dep map: child name → list of direct parent names.
		// A parent is a top-level node_modules entry (no nested path) that lists the child.
		reverseDeps := make(map[string][]string)
		for key, pkg := range lock.Packages {
			if key == "" {
				continue
			}
			parentName := packageNameFromKey(key)
			// Only map from top-level entries to avoid deeply nested duplicates
			if strings.Count(key, "node_modules/") != 1 {
				continue
			}
			allDeps := make(map[string]string)
			for k, v := range pkg.Dependencies {
				allDeps[k] = v
			}
			for k, v := range pkg.OptionalDependencies {
				allDeps[k] = v
			}
			for childName := range allDeps {
				reverseDeps[childName] = append(reverseDeps[childName], parentName)
			}
		}

		// v2/v3 format: keys are "node_modules/foo" or "node_modules/foo/node_modules/bar"
		for key, pkg := range lock.Packages {
			if key == "" || pkg.Version == "" {
				continue // root package entry
			}
			name := packageNameFromKey(key)
			if name == "" {
				continue
			}
			pkgPath := ""
			if modulesRoot != "" {
				pkgPath = filepath.Join(path, key)
			}
			// A package is direct if it appears as a top-level node_modules entry
			// and has no parents in the reverse map (i.e. nothing pulled it in).
			isTopLevel := strings.Count(key, "node_modules/") == 1
			parents := reverseDeps[name]
			packages = append(packages, schema.Package{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				Scope:     "project",
				Direct:    isTopLevel && len(parents) == 0,
				Path:      pkgPath,
				Parents:   parents,
			})
		}
	} else if len(lock.Dependencies) > 0 {
		// v1 format — no dependency graph available
		for name, dep := range lock.Dependencies {
			pkgPath := ""
			if modulesRoot != "" {
				pkgPath = filepath.Join(modulesRoot, name)
			}
			packages = append(packages, schema.Package{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				Scope:     "project",
				Direct:    !dep.Dev,
				Path:      pkgPath,
			})
		}
	}

	return packages, nil
}

// packageNameFromKey extracts the npm package name from a package-lock v2/v3 key.
// "node_modules/foo"                    → "foo"
// "node_modules/@scope/foo"             → "@scope/foo"
// "node_modules/foo/node_modules/bar"   → "bar"
// "node_modules/foo/node_modules/@s/b"  → "@s/b"
func packageNameFromKey(key string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(key, marker)
	if idx < 0 {
		return ""
	}
	return key[idx+len(marker):]
}

// inspectNpmList falls back to npm list when no lock file exists.
func inspectNpmList(path string) ([]schema.Package, error) {
	cmd := exec.Command("npm", "list", "--json", "--depth=0")
	cmd.Dir = path
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}

	var raw struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	modulesRoot := filepath.Join(path, "node_modules")
	var packages []schema.Package
	for name, dep := range raw.Dependencies {
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
			Scope:     "project",
			Direct:    true,
			Path:      filepath.Join(modulesRoot, name),
		})
	}
	return packages, nil
}
