package intercept

import (
	"fmt"
	"os"
	"strings"
)

const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiRed       = "\033[31m"
	ansiRedBold   = "\033[1;31m"
	ansiYellow    = "\033[33m"
	ansiWhite     = "\033[97m"
	ansiGray      = "\033[90m"
	ansiBgRed     = "\033[41m"
)

func noColor() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"
}

func color(codes ...string) string {
	if noColor() {
		return ""
	}
	return strings.Join(codes, "")
}

func reset() string {
	if noColor() {
		return ""
	}
	return ansiReset
}

// BlockedPackage holds one match to display in the blocked output.
type BlockedPackage struct {
	Name    string
	Version string
	Reason  string
	Sources []string
}

// PrintBlocked writes a high-visibility blocked-install warning to stderr.
// It is intentionally loud — it must stand out from surrounding npm/pip output.
func PrintBlocked(manager string, pkgs []BlockedPackage) {
	w := os.Stderr

	termWidth := terminalWidth()

	// ── Banner ────────────────────────────────────────────────────────────────
	label := "  DEVSCAN BLOCKED  "
	inner := termWidth - 2
	padding := inner - len(label)
	if padding < 0 {
		padding = 0
	}
	padLeft := padding / 2
	padRight := padding - padLeft

	top := "╔" + strings.Repeat("═", inner) + "╗"
	mid := "║" + strings.Repeat(" ", padLeft) + label + strings.Repeat(" ", padRight) + "║"
	bot := "╚" + strings.Repeat("═", inner) + "╝"

	fmt.Fprintln(w)
	fmt.Fprintln(w, color(ansiBgRed, ansiBold, ansiWhite)+top+reset())
	fmt.Fprintln(w, color(ansiBgRed, ansiBold, ansiWhite)+mid+reset())
	fmt.Fprintln(w, color(ansiBgRed, ansiBold, ansiWhite)+bot+reset())
	fmt.Fprintln(w)

	// ── Per-package findings ──────────────────────────────────────────────────
	for _, pkg := range pkgs {
		reason := pkg.Reason
		if reason == "" {
			reason = "SUPPLY-CHAIN ATTACK"
		}

		fmt.Fprintf(w, "  %s%-10s%s  %s%s@%s%s\n",
			color(ansiRedBold), "["+reason+"]", reset(),
			color(ansiBold), pkg.Name, pkg.Version, reset(),
		)

		if len(pkg.Sources) > 0 {
			fmt.Fprintf(w, "  %s%-10s%s  Found in: %s\n",
				color(ansiGray), "", reset(),
				strings.Join(pkg.Sources, ", "),
			)
		}
		fmt.Fprintln(w)
	}

	// ── Footer ────────────────────────────────────────────────────────────────
	fmt.Fprintf(w, "  %s%s install was blocked.%s Remove %s from your command and try again.\n",
		color(ansiRedBold),
		manager,
		reset(),
		pluralPackage(len(pkgs)),
	)
	fmt.Fprintf(w, "  Run %sdevscan audit%s for a full vulnerability report.\n",
		color(ansiBold), reset(),
	)
	fmt.Fprintln(w)
}

func pluralPackage(n int) string {
	if n == 1 {
		return "this package"
	}
	return "these packages"
}

// terminalWidth returns the current terminal width, defaulting to 72.
func terminalWidth() int {
	// Try to read from the kernel without importing a full terminal library.
	// Falls back gracefully if stdout is not a tty (CI, pipes).
	if w := termWidth(); w > 20 {
		return w
	}
	return 72
}
