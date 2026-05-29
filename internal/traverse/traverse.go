package traverse

import (
	"os"
	"path/filepath"
)

// manifests are filenames that indicate a project root for a given ecosystem.
var manifests = []string{
	"package.json",    // npm
	"requirements.txt", // pip
	"Pipfile",          // pip
	"pyproject.toml",   // pip
	"composer.json",   // composer
	"Cargo.toml",      // cargo
	"go.mod",          // go
}

// FindProjects walks root up to maxDepth levels deep and returns directories
// that contain at least one known project manifest. The root itself is always
// included if it contains a manifest.
func FindProjects(root string, maxDepth int) []string {
	var found []string
	seen := map[string]bool{}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}

		if hasManifest(dir) && !seen[dir] {
			seen[dir] = true
			found = append(found, dir)
		}

		if depth == maxDepth {
			return
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			// Skip hidden dirs, node_modules, vendor, and other noise.
			if name[0] == '.' || name == "node_modules" || name == "vendor" ||
				name == "target" || name == ".git" || name == "dist" || name == "build" {
				continue
			}
			walk(filepath.Join(dir, name), depth+1)
		}
	}

	walk(root, 0)
	return found
}

func hasManifest(dir string) bool {
	for _, m := range manifests {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}
