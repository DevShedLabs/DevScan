package intercept

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/DevShedLabs/devscan/internal/intercept/managers"
	"github.com/DevShedLabs/devscan/internal/schema"
)

// ShimsDir returns ~/.devscan/shims.
func ShimsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".devscan", "shims"), nil
}

// IsShimName reports whether name matches a binary managed by any known manager.
func IsShimName(name string) bool {
	return managers.ByName(name) != nil
}

// Enable writes shim symlinks for all managers and patches shell profiles.
func Enable() error {
	shimsDir, err := ShimsDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(shimsDir, 0o755); err != nil {
		return err
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}

	for _, m := range managers.All() {
		for _, bin := range m.Binaries() {
			shimPath := filepath.Join(shimsDir, bin)
			_ = os.Remove(shimPath)
			if err := os.Symlink(self, shimPath); err != nil {
				return fmt.Errorf("could not create shim for %s: %w", bin, err)
			}
		}
	}

	if err := patchShellProfiles(shimsDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not patch shell profile: %v\n", err)
		fmt.Fprintf(os.Stderr, "Add this to your shell profile manually:\n")
		fmt.Fprintf(os.Stderr, "  export PATH=%q:$PATH\n", shimsDir)
	}

	return nil
}

// Disable removes shim symlinks and the PATH entry from shell profiles.
func Disable() error {
	shimsDir, err := ShimsDir()
	if err != nil {
		return err
	}

	for _, m := range managers.All() {
		for _, bin := range m.Binaries() {
			_ = os.Remove(filepath.Join(shimsDir, bin))
		}
	}

	_ = unpatchShellProfiles(shimsDir)
	return nil
}

// EnsureShims rewrites shims to point at the current executable.
// Called automatically during `devscan update` to keep shims current.
func EnsureShims() error {
	shimsDir, err := ShimsDir()
	if err != nil {
		return err
	}
	// Only act if intercept has been enabled (shims dir exists with at least one shim).
	if _, err := os.Stat(shimsDir); os.IsNotExist(err) {
		return nil
	}
	return Enable()
}

// Status returns which shims are currently active.
func Status() ([]ShimStatus, error) {
	shimsDir, err := ShimsDir()
	if err != nil {
		return nil, err
	}

	var out []ShimStatus
	for _, m := range managers.All() {
		for _, bin := range m.Binaries() {
			shimPath := filepath.Join(shimsDir, bin)
			active := false
			if target, err := os.Readlink(shimPath); err == nil {
				self, _ := os.Executable()
				active = target == self
			}
			out = append(out, ShimStatus{Binary: bin, Manager: m.Name(), Active: active, Path: shimPath})
		}
	}
	return out, nil
}

type ShimStatus struct {
	Binary  string
	Manager string
	Active  bool
	Path    string
}

// RunShim is called when the devscan binary is invoked as a shim (argv[0] is
// a package manager name). It checks packages against the blocklist and either
// blocks or execs the real binary.
func RunShim(name string, args []string) {
	m := managers.ByName(name)
	if m == nil {
		// Unknown manager — just exec whatever is on PATH after our shims.
		execReal(name, args)
		return
	}

	shimsDir, err := ShimsDir()
	if err != nil {
		execReal(name, args)
		return
	}

	pkgs, mode, err := m.ParseInstall(args)
	if err != nil || mode == managers.ModePassthrough {
		execRealBinary(m, shimsDir, args)
		return
	}

	if mode == managers.ModeLockfile {
		// Read packages from the lock file in the current working directory.
		cwd, _ := os.Getwd()
		lockPkgs, err := managers.ReadLockfile(m.Name(), cwd)
		if err != nil || len(lockPkgs) == 0 {
			// No lock file or unreadable — pass through without blocking.
			execRealBinary(m, shimsDir, args)
			return
		}
		pkgs = lockPkgs
	}

	// Resolve versions for any unpinned packages.
	for i, pkg := range pkgs {
		if pkg.Version == "" {
			if v, err := m.ResolveVersion(pkg.Name); err == nil {
				pkgs[i].Version = v
			}
		}
	}

	blocked, err := advisory.MatchBlocklists(toSchemaPkgs(pkgs, m.Name()))
	if err != nil || len(blocked) == 0 {
		execRealBinary(m, shimsDir, args)
		return
	}

	// Convert blocklist hits to BlockedPackage for the warning renderer.
	var display []BlockedPackage
	for _, v := range blocked {
		sources, reason := parseBlocklistDesc(v.Description)
		display = append(display, BlockedPackage{
			Name:    v.Package,
			Version: v.InstalledVersion,
			Reason:  reason,
			Sources: sources,
		})
	}

	PrintBlocked(m.Name(), display)
	os.Exit(1)
}

func execRealBinary(m managers.Manager, shimsDir string, args []string) {
	real, err := m.FindReal(shimsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "devscan shim: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Exec(real, append([]string{real}, args...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "devscan shim: exec failed: %v\n", err)
		os.Exit(1)
	}
}

func execReal(name string, args []string) {
	path, err := exec.LookPath(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "devscan shim: %s not found\n", name)
		os.Exit(1)
	}
	if err := syscall.Exec(path, append([]string{path}, args...), os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "devscan shim: exec failed: %v\n", err)
		os.Exit(1)
	}
}

func toSchemaPkgs(pkgs []managers.Pkg, ecosystem string) []schema.Package {
	out := make([]schema.Package, len(pkgs))
	for i, p := range pkgs {
		out[i] = schema.Package{Name: p.Name, Version: p.Version, Ecosystem: ecosystem}
	}
	return out
}


// parseBlocklistDesc extracts sources and reason from the Description field
// written by advisory.MatchBlocklists.
func parseBlocklistDesc(desc string) (sources []string, reason string) {
	// Format: "This package appears in <sources>. Reason: <reason>. Remove…"
	rest := strings.TrimPrefix(desc, "This package appears in ")
	if idx := strings.Index(rest, ". Reason: "); idx >= 0 {
		srcPart := rest[:idx]
		reasonPart := rest[idx+len(". Reason: "):]
		if end := strings.Index(reasonPart, "."); end >= 0 {
			reasonPart = reasonPart[:end]
		}
		for _, s := range strings.Split(srcPart, ", ") {
			if s = strings.TrimSpace(s); s != "" {
				sources = append(sources, s)
			}
		}
		reason = reasonPart
	}
	return
}
