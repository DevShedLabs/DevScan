package inspectors

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type GemInspector struct{}

func (i *GemInspector) Name() string      { return "gem" }
func (i *GemInspector) Ecosystem() string { return "gem" }

func (i *GemInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if scope == "project" {
		if path == "" {
			return nil, nil
		}
		// Only scan if this directory has a Gemfile.
		if _, err := os.Stat(filepath.Join(path, "Gemfile")); err != nil {
			return nil, nil
		}
		return inspectGemfileLock(path)
	}

	if _, err := exec.LookPath("gem"); err != nil {
		return nil, nil
	}

	cmd := exec.Command("gem", "list", "--no-verbose", "--no-user-install")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var packages []schema.Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name, version, ok := parseGemLine(line)
		if !ok {
			continue
		}
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "gem",
			Scope:     scope,
			Direct:    true,
		})
	}
	return packages, nil
}

// inspectGemfileLock reads Gemfile.lock and returns all locked gems.
func inspectGemfileLock(path string) ([]schema.Package, error) {
	lockPath := filepath.Join(path, "Gemfile.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		// No lockfile — nothing to report.
		return nil, nil
	}
	defer f.Close()

	var packages []schema.Package
	inGems := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "GEM" || trimmed == "GIT" || trimmed == "PATH" {
			inGems = true
			continue
		}
		// A new top-level section (no leading whitespace) ends the gems block.
		if inGems && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inGems = false
		}
		if !inGems {
			continue
		}
		// Gem entries are indented with exactly 4 spaces: "    name (version)"
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		name, version, ok := parseGemLine(trimmed)
		if !ok {
			continue
		}
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "gem",
			Scope:     "project",
			Direct:    true,
			Path:      lockPath,
		})
	}
	return packages, scanner.Err()
}

// parseGemLine parses "bundler (2.5.6)" or "rails (7.1.0, 6.1.7)" → name, latest version.
func parseGemLine(line string) (name, version string, ok bool) {
	open := strings.Index(line, " (")
	close := strings.LastIndex(line, ")")
	if open < 0 || close < 0 || close <= open {
		return "", "", false
	}
	name = strings.TrimSpace(line[:open])
	versions := strings.Split(line[open+2:close], ", ")
	if len(versions) == 0 {
		return "", "", false
	}
	v := strings.TrimSpace(versions[0])
	if strings.Contains(v, "default") {
		return "", "", false
	}
	return name, v, true
}
