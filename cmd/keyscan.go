package cmd

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"time"

	"github.com/DevShedLabs/devscan/internal/keyscanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keyscanCmd = &cobra.Command{
	Use:   "keyscan",
	Short: "Scan files for exposed secrets and API keys",
	Long: `Scans source files for exposed secrets including API keys, tokens, private keys,
and service credentials. Skips binary files, node_modules, vendor directories,
and other non-source paths.

Formats: table (default), json, md, html
Use --output to write results to a file instead of stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		scanPath, _ := cmd.Flags().GetString("path")
		if scanPath == "" {
			scanPath = viper.GetString("path")
		}
		if scanPath == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cannot determine working directory: %w", err)
			}
			scanPath = cwd
		}

		minSeverity, _ := cmd.Flags().GetString("severity")
		depth, _ := cmd.Flags().GetInt("depth")
		outputFile, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")
		if format == "" {
			format = viper.GetString("format")
		}
		if format == "" {
			format = "table"
		}

		showProgress := outputFile != "" || !isTerminal(os.Stdout)
		var fileCount int
		start := time.Now()

		opts := keyscanner.Options{MaxDepth: depth}
		opts.Progress = func(path string) {
			fileCount++
			if showProgress && fileCount%50 == 0 {
				fmt.Fprintf(os.Stderr, "\r\033[Kscanning... %d files, %s elapsed", fileCount, formatKeyscanDuration(time.Since(start)))
			}
		}

		findings, err := keyscanner.ScanWithOptions(scanPath, opts)
		if showProgress && fileCount > 0 {
			fmt.Fprintf(os.Stderr, "\r\033[K") // clear progress line
		}
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		findings = filterBySeverityKeyscan(findings, keyscanner.Severity(minSeverity))

		// Resolve output writer
		out := io.Writer(os.Stdout)
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("could not create output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		duration := time.Since(start)

		switch format {
		case "json":
			if err := renderKeyscanJSON(out, findings, scanPath); err != nil {
				return err
			}
		case "md", "markdown":
			if err := renderKeyscanMarkdown(out, findings, scanPath, fileCount, duration); err != nil {
				return err
			}
		case "html":
			if err := renderKeyscanHTML(out, findings, scanPath, fileCount, duration); err != nil {
				return err
			}
		default:
			if err := renderKeyscanTable(out, findings, scanPath); err != nil {
				return err
			}
		}

		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "Report written to %s\n", outputFile)
		}

		if len(findings) > 0 {
			os.Exit(2)
		}
		return nil
	},
}

func filterBySeverityKeyscan(findings []keyscanner.Finding, min keyscanner.Severity) []keyscanner.Finding {
	rank := map[keyscanner.Severity]int{
		keyscanner.SeverityCritical: 4,
		keyscanner.SeverityHigh:     3,
		keyscanner.SeverityMedium:   2,
		keyscanner.SeverityLow:      1,
	}
	minRank, ok := rank[min]
	if !ok {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if rank[f.Severity] >= minRank {
			out = append(out, f)
		}
	}
	return out
}

func renderKeyscanTable(w io.Writer, findings []keyscanner.Finding, scanPath string) error {
	fmt.Fprintf(w, "Scanning: %s\n\n", scanPath)

	if len(findings) == 0 {
		fmt.Fprintln(w, "No secrets found.")
		return nil
	}

	for _, f := range findings {
		fmt.Fprintf(w, "%s %s\n", keyscanBadge(f.Severity), f.RuleName)
		fmt.Fprintf(w, "  file:  %s:%d\n", f.File, f.Line)
		fmt.Fprintf(w, "  match: %s\n\n", f.Match)
	}

	counts := keyscanCounts(findings)
	fmt.Fprintf(w, "Found %d secret(s): ", len(findings))
	sep := ""
	for _, label := range []string{"critical", "high", "medium", "low"} {
		if n := counts[label]; n > 0 {
			fmt.Fprintf(w, "%s%d %s", sep, n, label)
			sep = ", "
		}
	}
	fmt.Fprintln(w)
	return nil
}

func renderKeyscanJSON(w io.Writer, findings []keyscanner.Finding, scanPath string) error {
	if findings == nil {
		findings = []keyscanner.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Path     string               `json:"path"`
		Findings []keyscanner.Finding `json:"findings"`
		Total    int                  `json:"total"`
	}{
		Path:     scanPath,
		Findings: findings,
		Total:    len(findings),
	})
}

func renderKeyscanMarkdown(w io.Writer, findings []keyscanner.Finding, scanPath string, fileCount int, duration time.Duration) error {
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }

	p("# KeyScan Report")
	p("")
	p("**Path:** `%s`  ", scanPath)
	p("**Files scanned:** %d  ", fileCount)
	p("**Duration:** %s  ", formatKeyscanDuration(duration))
	p("**Secrets found:** %d  ", len(findings))
	p("")

	counts := keyscanCounts(findings)
	p("## Summary")
	p("")
	p("| Severity | Count |")
	p("|---|---|")
	for _, label := range []string{"critical", "high", "medium", "low"} {
		p("| %s | %d |", label, counts[label])
	}
	p("")

	if len(findings) == 0 {
		p("No secrets found.")
		return nil
	}

	p("## Findings")
	p("")

	for _, sev := range []keyscanner.Severity{
		keyscanner.SeverityCritical,
		keyscanner.SeverityHigh,
		keyscanner.SeverityMedium,
		keyscanner.SeverityLow,
	} {
		var group []keyscanner.Finding
		for _, f := range findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		p("### %s", keyscanSeverityHeading(sev))
		p("")
		p("| Rule | File | Line | Match |")
		p("|---|---|---|---|")
		for _, f := range group {
			p("| `%s` | `%s` | %d | `%s` |", f.RuleName, f.File, f.Line, f.Match)
		}
		p("")
	}

	p("---")
	p("*Generated by [devscan](https://github.com/DevShedLabs/devscan)*")
	return nil
}

func renderKeyscanHTML(w io.Writer, findings []keyscanner.Finding, scanPath string, fileCount int, duration time.Duration) error {
	p := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }

	counts := keyscanCounts(findings)

	p(`<!DOCTYPE html>`)
	p(`<html lang="en">`)
	p(`<head>`)
	p(`<meta charset="UTF-8">`)
	p(`<meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	p(`<title>KeyScan Report — %s</title>`, html.EscapeString(scanPath))
	p(`<style>%s</style>`, keyscanCSS())
	p(`</head>`)
	p(`<body>`)

	p(`<header>`)
	p(`  <div class="logo">KeyScan</div>`)
	p(`  <div class="meta">`)
	p(`    <span>Path: <code>%s</code></span>`, html.EscapeString(scanPath))
	p(`    <span>Files scanned: <strong>%d</strong></span>`, fileCount)
	p(`    <span>Duration: <strong>%s</strong></span>`, html.EscapeString(formatKeyscanDuration(duration)))
	p(`  </div>`)
	p(`</header>`)

	// Summary cards
	p(`<section class="summary">`)
	p(`  <div class="card total"><div class="card-value">%d</div><div class="card-label">Total Secrets</div></div>`, len(findings))
	p(`  <div class="card critical"><div class="card-value">%d</div><div class="card-label">Critical</div></div>`, counts["critical"])
	p(`  <div class="card high"><div class="card-value">%d</div><div class="card-label">High</div></div>`, counts["high"])
	p(`  <div class="card medium"><div class="card-value">%d</div><div class="card-label">Medium</div></div>`, counts["medium"])
	p(`  <div class="card low"><div class="card-value">%d</div><div class="card-label">Low</div></div>`, counts["low"])
	p(`</section>`)

	if len(findings) == 0 {
		p(`<section><p class="empty">No secrets found.</p></section>`)
	} else {
		p(`<section>`)
		p(`  <h2 class="section-heading">Findings <span class="heading-count">%d</span></h2>`, len(findings))

		for _, sev := range []keyscanner.Severity{
			keyscanner.SeverityCritical,
			keyscanner.SeverityHigh,
			keyscanner.SeverityMedium,
			keyscanner.SeverityLow,
		} {
			var group []keyscanner.Finding
			for _, f := range findings {
				if f.Severity == sev {
					group = append(group, f)
				}
			}
			if len(group) == 0 {
				continue
			}
			p(`  <h3 class="sev-%s">%s</h3>`, string(sev), keyscanSeverityHeading(sev))
			p(`  <table>`)
			p(`    <thead><tr><th>Rule</th><th>File</th><th>Line</th><th>Match</th></tr></thead>`)
			p(`    <tbody>`)
			for _, f := range group {
				p(`      <tr><td><code>%s</code></td><td><code>%s</code></td><td>%d</td><td><code>%s</code></td></tr>`,
					html.EscapeString(f.RuleName),
					html.EscapeString(f.File),
					f.Line,
					html.EscapeString(f.Match),
				)
			}
			p(`    </tbody>`)
			p(`  </table>`)
		}
		p(`</section>`)
	}

	p(`<footer><p>Generated by <a href="https://github.com/DevShedLabs/devscan">devscan</a></p></footer>`)
	p(`</body>`)
	p(`</html>`)
	return nil
}

func keyscanBadge(s keyscanner.Severity) string {
	switch s {
	case keyscanner.SeverityCritical:
		return "\033[31;1m[CRIT]\033[0m"
	case keyscanner.SeverityHigh:
		return "\033[31m[HIGH]\033[0m"
	case keyscanner.SeverityMedium:
		return "\033[33m[MED] \033[0m"
	case keyscanner.SeverityLow:
		return "\033[90m[LOW] \033[0m"
	default:
		return "[?]   "
	}
}

func keyscanSeverityHeading(s keyscanner.Severity) string {
	switch s {
	case keyscanner.SeverityCritical:
		return "🔴 Critical"
	case keyscanner.SeverityHigh:
		return "🟠 High"
	case keyscanner.SeverityMedium:
		return "🟡 Medium"
	case keyscanner.SeverityLow:
		return "🟢 Low"
	default:
		return "⚪ Unknown"
	}
}

func keyscanCounts(findings []keyscanner.Finding) map[string]int {
	m := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range findings {
		m[string(f.Severity)]++
	}
	return m
}

func formatKeyscanDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm %ds", mins, secs)
}

func keyscanCSS() string {
	return `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 14px; line-height: 1.6; color: #1a1a1a; background: #f5f5f5; }
header { background: #111; color: #fff; padding: 20px 32px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
.logo { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; color: #fff; }
.meta { display: flex; gap: 20px; flex-wrap: wrap; font-size: 13px; color: #aaa; }
.meta strong { color: #fff; }
.meta code { color: #93c5fd; background: rgba(255,255,255,0.1); padding: 1px 4px; border-radius: 3px; }
section { max-width: 1100px; margin: 32px auto; padding: 0 24px; }
h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; color: #111; }
h2.section-heading { display: flex; align-items: center; justify-content: space-between; }
.heading-count { font-size: 13px; font-weight: 600; color: #6b7280; background: #e5e7eb; padding: 2px 10px; border-radius: 99px; }
h3 { font-size: 15px; font-weight: 600; margin: 24px 0 12px; }
.sev-critical { color: #dc2626; }
.sev-high     { color: #ea580c; }
.sev-medium   { color: #ca8a04; }
.sev-low      { color: #16a34a; }
.summary { display: flex; gap: 16px; flex-wrap: wrap; max-width: 1100px; margin: 24px auto 0; padding: 0 24px; }
.card { background: #fff; border-radius: 8px; padding: 16px 20px; min-width: 110px; text-align: center; border: 1px solid #e5e7eb; flex: 1; }
.card-value { font-size: 28px; font-weight: 700; color: #111; }
.card-label { font-size: 12px; color: #6b7280; margin-top: 2px; }
.card.critical .card-value { color: #dc2626; }
.card.high     .card-value { color: #ea580c; }
.card.medium   .card-value { color: #ca8a04; }
.card.low      .card-value { color: #16a34a; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; border: 1px solid #e5e7eb; font-size: 13px; margin-bottom: 16px; }
thead { background: #f9fafb; }
th { padding: 10px 14px; text-align: left; font-weight: 600; color: #374151; border-bottom: 1px solid #e5e7eb; }
td { padding: 9px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: top; word-break: break-all; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafafa; }
code { font-family: "SF Mono","Fira Code",monospace; font-size: 12px; background: #f3f4f6; padding: 1px 5px; border-radius: 3px; color: #374151; }
a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }
.empty { color: #6b7280; font-style: italic; }
footer { text-align: center; padding: 24px; color: #9ca3af; font-size: 12px; border-top: 1px solid #e5e7eb; margin-top: 48px; }
`
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func init() {
	rootCmd.AddCommand(keyscanCmd)
	keyscanCmd.Flags().String("path", "", "Directory to scan (default: current directory)")
	keyscanCmd.Flags().String("severity", "", "Minimum severity to report: critical, high, medium, low")
	keyscanCmd.Flags().Int("depth", 0, "Maximum directory depth to scan (0 = unlimited)")
	keyscanCmd.Flags().StringP("output", "o", "", "Write report to file instead of stdout")
	keyscanCmd.Flags().String("format", "", "Output format: table, json, md, html (default: table)")
}
