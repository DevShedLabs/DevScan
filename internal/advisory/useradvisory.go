package advisory

import (
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// UserAdvisory is one entry in a .devscan/advisories.yaml file.
type UserAdvisory struct {
	Ecosystem string `yaml:"ecosystem"`
	Package   string `yaml:"package"`
	// Version may be a specific version ("1.2.3") or "*" / "" to match all versions.
	Version   string `yaml:"version"`
	Severity  string `yaml:"severity"`
	Reason    string `yaml:"reason"`
	Reference string `yaml:"reference"`
}

type userAdvisoryFile struct {
	Advisories []UserAdvisory `yaml:"advisories"`
}

// userAdvisoryPaths returns the candidate locations for advisories.yaml files,
// ordered from most-local to most-global:
//  1. .devscan/advisories.yaml in the current working directory
//  2. ~/.devscan/advisories.yaml (global user advisory)
func userAdvisoryPaths() []string {
	var paths []string
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, ".devscan", "advisories.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".devscan", "advisories.yaml"))
	}
	return paths
}

// loadUserAdvisories reads all advisories.yaml files and returns them as
// blocklistEntry values ready to merge with the compiled blocklist.
func loadUserAdvisories() ([]blocklistEntry, error) {
	var entries []blocklistEntry

	for _, path := range userAdvisoryPaths() {
		got, err := parseUserAdvisoryFile(path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, got...)
	}
	return entries, nil
}

func parseUserAdvisoryFile(path string) ([]blocklistEntry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var f userAdvisoryFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	source := filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
	var entries []blocklistEntry

	for _, a := range f.Advisories {
		if a.Package == "" {
			continue
		}

		// Normalise "*" to empty string — empty means "any version" internally.
		ver := strings.TrimSpace(a.Version)
		if ver == "*" {
			ver = ""
		}

		reason := a.Reason
		if a.Reference != "" {
			if reason != "" {
				reason += " — " + a.Reference
			} else {
				reason = a.Reference
			}
		}

		entries = append(entries, blocklistEntry{
			ecosystem: strings.ToLower(strings.TrimSpace(a.Ecosystem)),
			name:      strings.TrimSpace(a.Package),
			version:   ver,
			reason:    reason,
			sources:   []string{source},
		})
	}
	return entries, nil
}
