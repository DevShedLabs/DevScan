package inspectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type ComposerInspector struct{}

func (i *ComposerInspector) Name() string      { return "composer" }
func (i *ComposerInspector) Ecosystem() string { return "packagist" }

func (i *ComposerInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if scope == "project" {
		if path == "" {
			return nil, nil
		}
		composerjson, err := safeJoin(path, "composer.json")
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(composerjson); err != nil {
			return nil, nil
		}
		return inspectComposerLock(path)
	}

	if _, err := exec.LookPath("composer"); err != nil {
		return nil, nil
	}

	cmd := exec.Command("composer", "show", "--format=json", "--no-interaction", "--global")
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
		} `json:"installed"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(raw.Installed))
	for _, p := range raw.Installed {
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   strings.TrimPrefix(p.Version, "v"),
			Ecosystem: "packagist",
			Scope:     scope,
			Direct:    true,
		})
	}
	return packages, nil
}

// inspectComposerLock reads composer.lock and returns all locked packages with
// accurate versions, avoiding the stale-cache problem of `composer show`.
func inspectComposerLock(path string) ([]schema.Package, error) {
	lockPath, err := safeJoin(path, "composer.lock")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(lockPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var lock struct {
		Packages    []composerLockPkg `json:"packages"`
		PackagesDev []composerLockPkg `json:"packages-dev"`
	}
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, err
	}

	vendorDir := filepath.Join(path, "vendor")
	all := append(lock.Packages, lock.PackagesDev...)

	// Build reverse dep map: child → list of parents that require it.
	// Read direct deps from composer.json to identify top-level packages.
	directDeps := composerDirectDeps(path)
	reverseDeps := make(map[string][]string)
	for _, p := range all {
		for dep := range p.Require {
			if !isComposerPlatformReq(dep) {
				reverseDeps[dep] = append(reverseDeps[dep], p.Name)
			}
		}
	}

	var packages []schema.Package
	for _, p := range all {
		pkgPath := filepath.Join(vendorDir, p.Name)
		if _, err := os.Stat(pkgPath); err != nil {
			pkgPath = ""
		}
		parents := reverseDeps[p.Name]
		_, isDirect := directDeps[p.Name]
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   strings.TrimPrefix(p.Version, "v"),
			Ecosystem: "packagist",
			Scope:     "project",
			Direct:    isDirect,
			Path:      pkgPath,
			Parents:   parents,
		})
	}
	return packages, nil
}

// composerDirectDeps reads composer.json and returns the set of directly required packages.
func composerDirectDeps(path string) map[string]bool {
	composerjson, err := safeJoin(path, "composer.json")
	if err != nil {
		return nil
	}
	f, err := os.Open(composerjson)
	if err != nil {
		return nil
	}
	defer f.Close()
	var cj struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.NewDecoder(f).Decode(&cj); err != nil {
		return nil
	}
	deps := make(map[string]bool)
	for k := range cj.Require {
		if !isComposerPlatformReq(k) {
			deps[k] = true
		}
	}
	for k := range cj.RequireDev {
		if !isComposerPlatformReq(k) {
			deps[k] = true
		}
	}
	return deps
}

// isComposerPlatformReq returns true for php/ext-*/lib-* requirements which are
// platform constraints, not installable packages.
func isComposerPlatformReq(name string) bool {
	return name == "php" || name == "composer-runtime-api" ||
		strings.HasPrefix(name, "ext-") ||
		strings.HasPrefix(name, "lib-") ||
		strings.HasPrefix(name, "php-")
}

type composerLockPkg struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}
