package intercept

import (
	"os"
	"path/filepath"
	"strings"
)

const pathMarkerStart = "# devscan-intercept-start"
const pathMarkerEnd = "# devscan-intercept-end"

// shellProfiles returns the shell config files to patch, in order of preference.
func shellProfiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	candidates := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".config", "fish", "config.fish"),
		filepath.Join(home, ".config", "nushell", "env.nu"),
	}

	// Only return files that already exist — don't create new ones.
	var found []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			found = append(found, p)
		}
	}
	return found
}

// pathExportLine returns the appropriate export line for a given shell file.
func pathExportLine(profile, shimsDir string) string {
	switch {
	case strings.HasSuffix(profile, "config.fish"):
		return "fish_add_path " + shimsDir
	case strings.HasSuffix(profile, "env.nu"):
		return `$env.PATH = ($env.PATH | prepend "` + shimsDir + `")`
	default:
		return `export PATH="` + shimsDir + `:$PATH"`
	}
}

func patchShellProfiles(shimsDir string) error {
	profiles := shellProfiles()
	if len(profiles) == 0 {
		return nil
	}

	var lastErr error
	for _, profile := range profiles {
		if err := patchProfile(profile, shimsDir); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func unpatchShellProfiles(shimsDir string) error {
	profiles := shellProfiles()
	var lastErr error
	for _, profile := range profiles {
		if err := unpatchProfile(profile); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func patchProfile(path, shimsDir string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Already patched — update the block in case shimsDir changed.
	if strings.Contains(string(content), pathMarkerStart) {
		if err := unpatchProfile(path); err != nil {
			return err
		}
		content, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	}

	block := "\n" + pathMarkerStart + "\n" +
		pathExportLine(path, shimsDir) + "\n" +
		pathMarkerEnd + "\n"

	return os.WriteFile(path, append(content, []byte(block)...), 0o644)
}

func unpatchProfile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	s := string(content)
	start := strings.Index(s, "\n"+pathMarkerStart)
	if start < 0 {
		return nil // not patched
	}
	end := strings.Index(s, pathMarkerEnd)
	if end < 0 {
		return nil
	}
	end += len(pathMarkerEnd) + 1 // include trailing newline

	cleaned := s[:start] + s[end:]
	return os.WriteFile(path, []byte(cleaned), 0o644)
}
