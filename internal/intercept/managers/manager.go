package managers

// InstallMode describes how a package manager resolves packages from a command.
type InstallMode int

const (
	// ModeExplicit means package names/versions were given on the command line.
	ModeExplicit InstallMode = iota
	// ModeLockfile means the command installs from a lockfile (npm ci, bun install).
	// Package names must be read from the lock file — not yet implemented.
	ModeLockfile
	// ModePassthrough means the subcommand is not an install (npm run, cargo build).
	// The shim should exec the real binary immediately with no checks.
	ModePassthrough
)

// Pkg is a package name and optional version extracted from an install command.
// Version is empty if it was not pinned on the command line.
type Pkg struct {
	Name    string
	Version string // empty = unresolved; shim will resolve via registry
}

// Manager abstracts a single package manager for the shim intercept layer.
type Manager interface {
	// Name returns the canonical name used in CLI output ("npm", "pip", …).
	Name() string

	// Binaries returns the executable names this manager owns.
	// Used to determine which shims to write.
	Binaries() []string

	// FindReal locates the real binary on PATH, skipping the shims directory.
	FindReal(shimsDir string) (string, error)

	// ParseInstall inspects the command-line arguments and returns the list of
	// packages the user intends to install, plus the install mode.
	// It must never return an error for unknown/passthrough subcommands —
	// those should return ModePassthrough with a nil package list.
	ParseInstall(args []string) ([]Pkg, InstallMode, error)

	// ResolveVersion contacts the package registry to find the latest published
	// version for a package whose version was not pinned on the command line.
	// Returns empty string if resolution fails — the shim should proceed
	// without a version check rather than block on a registry error.
	ResolveVersion(name string) (string, error)
}

// All returns every Manager implementation in a consistent order.
func All() []Manager {
	return []Manager{
		&NPM{},
		&Pnpm{},
		&Bun{},
		&Pip{},
		&Cargo{},
		&GoMod{},
		&Composer{},
		&VSCode{},
	}
}

// ByName returns the Manager whose Name() matches, or nil.
func ByName(name string) Manager {
	for _, m := range All() {
		if m.Name() == name {
			return m
		}
		for _, bin := range m.Binaries() {
			if bin == name {
				return m
			}
		}
	}
	return nil
}
