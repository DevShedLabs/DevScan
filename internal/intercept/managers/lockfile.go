package managers

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ReadLockfile reads the lock file for the given manager from dir and returns
// the full list of pinned packages. Returns nil if no lock file is found —
// callers should pass through without blocking in that case.
func ReadLockfile(managerName, dir string) ([]Pkg, error) {
	switch managerName {
	case "npm":
		return readNPMLockfile(dir)
	case "bun":
		return readBunLockfile(dir)
	case "composer":
		return readComposerLockfile(dir)
	case "go":
		return readGoSum(dir)
	default:
		return nil, nil
	}
}

// readNPMLockfile parses package-lock.json (lockfileVersion 2 and 3).
func readNPMLockfile(dir string) ([]Pkg, error) {
	path := filepath.Join(dir, "package-lock.json")
	f, err := os.Open(path)
	if err != nil {
		return nil, nil // no lock file is not an error
	}
	defer f.Close()

	var lock struct {
		Packages map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, err
	}

	var pkgs []Pkg
	for key, info := range lock.Packages {
		if key == "" || info.Version == "" {
			continue
		}
		// key is "node_modules/pkg" or "node_modules/@scope/pkg"
		name := strings.TrimPrefix(key, "node_modules/")
		pkgs = append(pkgs, Pkg{Name: name, Version: info.Version})
	}
	return pkgs, nil
}

// readBunLockfile parses bun.lock (v1 text format) or falls back to
// package-lock.json if bun.lock is absent.
//
// bun.lock is a custom text format — we look for lines like:
//   "pkg@version":
func readBunLockfile(dir string) ([]Pkg, error) {
	path := filepath.Join(dir, "bun.lock")
	f, err := os.Open(path)
	if err != nil {
		// bun.lock not present — try package-lock.json as fallback
		return readNPMLockfile(dir)
	}
	defer f.Close()

	var pkgs []Pkg
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Lines of interest: `"name@version": {`
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			continue
		}
		entry := line[1 : end+1]
		name, version := splitNameVersion(entry)
		if name != "" && version != "" {
			pkgs = append(pkgs, Pkg{Name: name, Version: version})
		}
	}
	return pkgs, scanner.Err()
}

// readComposerLockfile parses composer.lock.
func readComposerLockfile(dir string) ([]Pkg, error) {
	path := filepath.Join(dir, "composer.lock")
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, err
	}

	var pkgs []Pkg
	for _, p := range lock.Packages {
		if p.Name != "" && p.Version != "" {
			pkgs = append(pkgs, Pkg{
				Name:    p.Name,
				Version: strings.TrimPrefix(p.Version, "v"),
			})
		}
	}
	for _, p := range lock.PackagesDev {
		if p.Name != "" && p.Version != "" {
			pkgs = append(pkgs, Pkg{
				Name:    p.Name,
				Version: strings.TrimPrefix(p.Version, "v"),
			})
		}
	}
	return pkgs, nil
}

// readGoSum parses go.sum — each line is:
//
//	module@version h1:hash=
//	module@version/go.mod h1:hash=
//
// We only care about the module lines (not /go.mod lines).
func readGoSum(dir string) ([]Pkg, error) {
	path := filepath.Join(dir, "go.sum")
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var pkgs []Pkg
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		modver := parts[0] // "module@vX.Y.Z" or "module@vX.Y.Z/go.mod"
		if strings.Contains(modver, "/go.mod") {
			continue
		}
		at := strings.LastIndex(modver, "@")
		if at < 0 {
			continue
		}
		name := modver[:at]
		version := strings.TrimPrefix(modver[at+1:], "v")
		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, Pkg{Name: name, Version: version})
		}
	}
	return pkgs, scanner.Err()
}
