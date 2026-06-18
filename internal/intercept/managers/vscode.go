package managers

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VSCode handles `code --install-extension <id-or-vsix>` (also code-insiders
// and codium). It does NOT cover extensions installed from the GUI
// Extensions panel — that path never shells out to the code binary, so
// there's nothing for a shim to intercept. Pair this with a runtime check
// inside VS Code itself (e.g. an extension watching
// vscode.extensions.onDidChange) to cover that gap.
type VSCode struct{}

func (v *VSCode) Name() string       { return "vscode" }
func (v *VSCode) Binaries() []string { return []string{"code", "code-insiders", "codium"} }

func (v *VSCode) FindReal(shimsDir string) (string, error) {
	return findReal("code", shimsDir)
}

func (v *VSCode) ParseInstall(args []string) ([]Pkg, InstallMode, error) {
	var pkgs []Pkg
	found := false

	for i := 0; i < len(args); i++ {
		if args[i] != "--install-extension" {
			continue
		}
		found = true
		if i+1 >= len(args) {
			continue
		}
		target := args[i+1]
		i++

		if looksLikeVsixPath(target) {
			name, version, err := readVsixManifest(target)
			if err != nil {
				// Unreadable vsix — fail open rather than block on a parse error.
				continue
			}
			pkgs = append(pkgs, Pkg{Name: name, Version: version})
			continue
		}

		name, version := splitExtensionID(target)
		pkgs = append(pkgs, Pkg{Name: name, Version: version})
	}

	if !found || len(pkgs) == 0 {
		return nil, ModePassthrough, nil
	}
	return pkgs, ModeExplicit, nil
}

// ResolveVersion is a no-op here: blocklist/advisory entries for the
// "vscode" ecosystem are expected to use a wildcard version (omit Version
// in the CSV/YAML source), since these are almost always "block this
// publisher.name outright" rather than "block this exact release" — there's
// no registry equivalent to "latest published version" worth round-tripping
// for that purpose.
func (v *VSCode) ResolveVersion(name string) (string, error) {
	return "", nil
}

// splitExtensionID handles "publisher.name" and "publisher.name@1.2.3".
func splitExtensionID(target string) (string, string) {
	if idx := strings.LastIndex(target, "@"); idx > 0 {
		return target[:idx], target[idx+1:]
	}
	return target, ""
}

func looksLikeVsixPath(target string) bool {
	if strings.HasSuffix(strings.ToLower(target), ".vsix") {
		return true
	}
	_, err := os.Stat(target)
	return err == nil
}

// readVsixManifest opens a .vsix (a zip archive) and reads publisher/name/
// version from extension/package.json — no extraction to disk required.
func readVsixManifest(path string) (name string, version string, err error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", "", err
	}
	defer r.Close()

	for _, f := range r.File {
		if filepath.ToSlash(f.Name) != "extension/package.json" {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			return "", "", openErr
		}
		defer rc.Close()

		var manifest struct {
			Publisher string `json:"publisher"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		}
		if decodeErr := json.NewDecoder(rc).Decode(&manifest); decodeErr != nil {
			return "", "", decodeErr
		}
		if manifest.Publisher == "" || manifest.Name == "" {
			return "", "", fmt.Errorf("package.json missing publisher/name")
		}
		return manifest.Publisher + "." + manifest.Name, manifest.Version, nil
	}
	return "", "", fmt.Errorf("extension/package.json not found in vsix")
}
