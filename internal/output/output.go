package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type Format string

const (
	FormatTable   Format = "table"
	FormatJSON    Format = "json"
	FormatCompact Format = "compact"
)

var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
	colorGray   = "\033[90m"
)

func noColor() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"
}

func severityColor(s schema.Severity) string {
	if noColor() {
		return ""
	}
	switch s {
	case schema.SeverityCritical:
		return colorRed + colorBold
	case schema.SeverityHigh:
		return colorRed
	case schema.SeverityMedium:
		return colorYellow
	case schema.SeverityLow:
		return colorGray
	default:
		return ""
	}
}

func severityIcon(s schema.Severity) string {
	switch s {
	case schema.SeverityCritical:
		return "[CRIT]"
	case schema.SeverityHigh:
		return "[HIGH]"
	case schema.SeverityMedium:
		return "[MED] "
	case schema.SeverityLow:
		return "[LOW] "
	default:
		return "[?]   "
	}
}

func statusIcon(s schema.Status) string {
	switch s {
	case schema.StatusOK:
		if noColor() {
			return "ok"
		}
		return colorGreen + "✓" + colorReset
	case schema.StatusOutdated:
		if noColor() {
			return "outdated"
		}
		return colorYellow + "⚠" + colorReset
	case schema.StatusEOL:
		if noColor() {
			return "eol"
		}
		return colorRed + "✗" + colorReset
	default:
		return "?"
	}
}

// Render writes the report in the requested format to w.
func Render(w io.Writer, report *schema.Report, format Format) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, report)
	case FormatCompact:
		return renderCompact(w, report)
	default:
		return renderTable(w, report)
	}
}

func renderJSON(w io.Writer, report *schema.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderCompact(w io.Writer, report *schema.Report) error {
	s := report.Summary
	fmt.Fprintf(w, "runtimes=%d packages=%d vulns=%d outdated=%d\n",
		s.Runtimes, s.Packages,
		s.Vulnerabilities.Critical+s.Vulnerabilities.High+s.Vulnerabilities.Medium+s.Vulnerabilities.Low,
		s.Outdated,
	)
	return nil
}

func renderTable(w io.Writer, report *schema.Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Runtimes
	if len(report.Runtimes) > 0 {
		fmt.Fprintln(tw, bold("System:"))
		for _, r := range report.Runtimes {
			latest := ""
			if r.Latest != "" {
				latest = fmt.Sprintf("  (latest: %s)", r.Latest)
			}
			fmt.Fprintf(tw, "  %-10s\t%s\t%s%s\n",
				r.Name, r.Version, statusIcon(r.Status), latest)
		}
		fmt.Fprintln(tw)
	}

	// Vulnerabilities
	if len(report.Vulnerabilities) > 0 {
		fmt.Fprintln(tw, bold("Vulnerabilities:"))
		for _, v := range report.Vulnerabilities {
			color := severityColor(v.Severity)
			reset := ""
			if color != "" {
				reset = colorReset
			}
			fmt.Fprintf(tw, "  %s%s %s@%s%s\n",
				color, severityIcon(v.Severity), v.Package, v.InstalledVersion, reset)
			fmt.Fprintf(tw, "     %s\n", v.Title)
			if v.Fix != nil {
				fmt.Fprintf(tw, "     Fix: %s\n", v.Fix.Command)
			}
		}
		fmt.Fprintln(tw)
	}

	// Outdated
	if len(report.Outdated) > 0 {
		fmt.Fprintln(tw, bold("Outdated:"))
		for _, o := range report.Outdated {
			fmt.Fprintf(tw, "  %-20s\t%s → %s\t[%s]\n",
				o.Name, o.Current, o.Latest, o.Ecosystem)
		}
		fmt.Fprintln(tw)
	}

	// Summary
	s := report.Summary
	fmt.Fprintln(tw, bold("Summary:"))
	fmt.Fprintf(tw, "  Runtimes:\t%d\n", s.Runtimes)
	fmt.Fprintf(tw, "  Packages:\t%d\n", s.Packages)
	fmt.Fprintf(tw, "  Vulnerabilities:\t%s\n", vulnSummaryLine(s.Vulnerabilities))
	fmt.Fprintf(tw, "  Outdated:\t%d\n", s.Outdated)

	return tw.Flush()
}

func vulnSummaryLine(v schema.VulnSummary) string {
	parts := []string{}
	if v.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", v.Critical))
	}
	if v.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", v.High))
	}
	if v.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", v.Medium))
	}
	if v.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", v.Low))
	}
	if len(parts) == 0 {
		return colorGreen + "none" + colorReset
	}
	return strings.Join(parts, ", ")
}

func bold(s string) string {
	if noColor() {
		return s
	}
	return colorBold + s + colorReset
}
