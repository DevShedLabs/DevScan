package inspectors

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type BrewInspector struct{}

func (i *BrewInspector) Name() string      { return "brew" }
func (i *BrewInspector) Ecosystem() string { return "homebrew" }

// brewNameMap translates Homebrew formula names to Bitnami OSV names where they differ.
// Only include mappings where the formula and OSV package are truly equivalent —
// libpq is the PostgreSQL client library, not the server, so it is intentionally excluded.
var brewNameMap = map[string]string{
	"httpd":        "apache",
	"mariadb":      "mariadb",
	"mysql-client": "mysql",
}

// brewSkip are packages already covered by language-specific inspectors (pip, npm, etc.)
// so we avoid double-counting them in the Bitnami ecosystem.
var brewSkip = map[string]bool{
	"python":      true,
	"python@3.11": true,
	"python@3.12": true,
	"python@3.13": true,
	"python@3.14": true,
	"node":        true,
	"php":         true,
	"rust":        true,
	"go":          true,
}

// findBrew returns the path to the brew binary, checking common install locations
// in addition to PATH since compiled binaries don't inherit shell profiles.
func findBrew() string {
	if p, err := exec.LookPath("brew"); err == nil {
		return p
	}
	for _, candidate := range []string{
		"/opt/homebrew/bin/brew", // Apple Silicon
		"/usr/local/bin/brew",    // Intel Mac
		"/home/linuxbrew/.linuxbrew/bin/brew", // Linux
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func (i *BrewInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if scope != "global" {
		return nil, nil
	}
	brew := findBrew()
	if brew == "" {
		return nil, nil
	}

	// Prepend known Homebrew bin dirs to PATH so the brew script can locate
	// its own internals when running outside a login shell.
	brewBin := strings.TrimSuffix(brew, "/brew")
	augmentedPath := brewBin + ":" + os.Getenv("PATH")
	cmd := exec.Command(brew, "list", "--versions", "--formula")
	cmd.Env = append(os.Environ(), "PATH="+augmentedPath)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("brew inspector: %w", err)
	}

	var packages []schema.Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[0]
		if brewSkip[name] {
			continue
		}

		// Brew lists all installed versions; pick the highest.
		rawVersion := highestBrewVersion(fields[1:])
		version := stripBrewRevision(rawVersion)

		// Map to Bitnami name if needed.
		osvName := name
		if mapped, ok := brewNameMap[name]; ok {
			osvName = mapped
		}

		packages = append(packages, schema.Package{
			Name:      osvName,
			Version:   version,
			Ecosystem: "homebrew",
			Scope:     "global",
			Direct:    true,
		})
	}

	return packages, nil
}

// highestBrewVersion picks the highest semver from a list of version strings.
func highestBrewVersion(versions []string) string {
	best := versions[0]
	for _, v := range versions[1:] {
		if brewVerGT(v, best) {
			best = v
		}
	}
	return best
}

func brewVerGT(a, b string) bool {
	ap := parseBrewVer(a)
	bp := parseBrewVer(b)
	for i := range ap {
		if ap[i] != bp[i] {
			return ap[i] > bp[i]
		}
	}
	return false
}

func parseBrewVer(v string) [4]int {
	// Strip revision suffix "1.2.3_4" → split on "_"
	v = strings.Split(v, "_")[0]
	var a, b, c, d int
	parts := strings.Split(v, ".")
	if len(parts) >= 1 {
		fmt.Sscanf(parts[0], "%d", &a)
	}
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &b)
	}
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &c)
	}
	if len(parts) >= 4 {
		fmt.Sscanf(parts[3], "%d", &d)
	}
	return [4]int{a, b, c, d}
}

// stripBrewRevision removes Homebrew's _N revision suffix: "9.5.0_3" → "9.5.0".
func stripBrewRevision(v string) string {
	if idx := strings.LastIndex(v, "_"); idx != -1 {
		// Only strip if everything after _ is numeric.
		suffix := v[idx+1:]
		allDigits := len(suffix) > 0
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return v[:idx]
		}
	}
	return v
}
