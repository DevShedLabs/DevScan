package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/DevShedLabs/devscan/internal/report"
	"github.com/spf13/cobra"
)

var osvCmd = &cobra.Command{
	Use:   "osv [term]",
	Short: "Search OSV for advisories by package name, ID, or keyword",
	Example: `  devscan osv "onering"
  devscan osv CVE-2024-1234
  devscan osv --package axios
  devscan osv --package axios --version 1.2.3
  devscan osv --package axios --ecosystem npm
  devscan osv --package axios --detail
  devscan osv --package axios --output report.html`,
	RunE: func(cmd *cobra.Command, args []string) error {
		pkg, _ := cmd.Flags().GetString("package")
		version, _ := cmd.Flags().GetString("version")
		ecosystem, _ := cmd.Flags().GetString("ecosystem")
		detail, _ := cmd.Flags().GetBool("detail")
		outputFile, _ := cmd.Flags().GetString("output")

		// Resolve OSV ecosystem name if user passed our internal name.
		if eco, ok := osvEcosystemNames[strings.ToLower(ecosystem)]; ok {
			ecosystem = eco
		}

		var advisories []advisory.OSVAdvisory
		var err error

		switch {
		case pkg != "":
			advisories, err = advisory.SearchByPackage(pkg, ecosystem, version, false)
		case len(args) > 0:
			term := args[0]
			// Direct ID lookup if it looks like a CVE, GHSA, or OSV ID.
			if isAdvisoryID(term) {
				a, lookupErr := advisory.LookupID(term)
				if lookupErr != nil {
					return lookupErr
				}
				advisories = []advisory.OSVAdvisory{*a}
			} else {
				advisories, err = advisory.SearchFreeText(term, ecosystem)
			}
		default:
			return fmt.Errorf("provide a search term or --package flag\n\nExamples:\n  devscan osv \"onering\"\n  devscan osv --package axios --version 1.2.3")
		}

		if err != nil {
			return err
		}

		if len(advisories) == 0 {
			fmt.Fprintln(os.Stderr, "No advisories found.")
			return nil
		}

		// Determine output format from file extension or flags.
		outFormat, err := resolveOSVFormat(cmd, outputFile)
		if err != nil {
			return err
		}

		out := os.Stdout
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("could not create output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		switch outFormat {
		case "html":
			if err := report.RenderOSVAdvisories(out, advisories, report.FormatHTML, detail); err != nil {
				return err
			}
		case "json":
			if err := report.RenderOSVAdvisories(out, advisories, report.FormatJSON, detail); err != nil {
				return err
			}
		case "md":
			if err := report.RenderOSVAdvisories(out, advisories, report.FormatMarkdown, detail); err != nil {
				return err
			}
		default:
			renderOSVTable(out, advisories, detail)
		}

		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "Report written to %s\n", outputFile)
		}
		return nil
	},
}

// osvEcosystemNames maps our short names to OSV ecosystem names.
var osvEcosystemNames = map[string]string{
	"npm":       "npm",
	"pypi":      "PyPI",
	"gem":       "RubyGems",
	"ruby":      "RubyGems",
	"go":        "Go",
	"cargo":     "crates.io",
	"crates.io": "crates.io",
	"rust":      "crates.io",
	"composer":  "Packagist",
	"packagist": "Packagist",
	"php":       "Packagist",
}

func isAdvisoryID(s string) bool {
	up := strings.ToUpper(s)
	return strings.HasPrefix(up, "CVE-") ||
		strings.HasPrefix(up, "GHSA-") ||
		strings.HasPrefix(up, "OSV-") ||
		strings.HasPrefix(up, "RUSTSEC-") ||
		strings.HasPrefix(up, "GO-") ||
		strings.HasPrefix(up, "PYSEC-") ||
		strings.HasPrefix(up, "NPM-")
}

func resolveOSVFormat(cmd *cobra.Command, outputFile string) (string, error) {
	html, _ := cmd.Flags().GetBool("html")
	md, _ := cmd.Flags().GetBool("md")
	jsonFmt, _ := cmd.Flags().GetBool("json")

	switch {
	case html:
		return "html", nil
	case md:
		return "md", nil
	case jsonFmt:
		return "json", nil
	case outputFile != "":
		switch strings.ToLower(filepath.Ext(outputFile)) {
		case ".html", ".htm":
			return "html", nil
		case ".json":
			return "json", nil
		case ".md", ".markdown":
			return "md", nil
		}
	}
	return "table", nil
}

func renderOSVTable(out *os.File, advisories []advisory.OSVAdvisory, detail bool) {
	sevColor := map[string]string{
		"critical": "\033[31;1m",
		"high":     "\033[31m",
		"medium":   "\033[33m",
		"low":      "\033[36m",
		"unknown":  "\033[37m",
	}
	reset := "\033[0m"

	fmt.Fprintf(out, "\n  Found %d advisor%s\n\n", len(advisories), pluralY(len(advisories)))

	for _, a := range advisories {
		sev := strings.ToLower(a.Severity)
		color := sevColor[sev]
		if color == "" {
			color = sevColor["unknown"]
		}

		sevTag := fmt.Sprintf("%s[%s]%s", color, strings.ToUpper(sev), reset)
		fmt.Fprintf(out, "  %s %s\n", sevTag, a.ID)

		if a.Package != "" {
			eco := a.Ecosystem
			if eco != "" {
				fmt.Fprintf(out, "  Package    %s (%s)\n", a.Package, eco)
			} else {
				fmt.Fprintf(out, "  Package    %s\n", a.Package)
			}
		}

		if a.Summary != "" {
			fmt.Fprintf(out, "  Summary    %s\n", a.Summary)
		}

		if detail {
			if a.Details != "" {
				fmt.Fprintf(out, "\n%s\n", indentBlock(a.Details, "             "))
			}
			for _, r := range a.Affected {
				if r.Fixed != "" {
					intro := r.Introduced
					if intro == "" {
						intro = "0"
					}
					fmt.Fprintf(out, "  Affected   >= %s, fixed in %s\n", intro, r.Fixed)
				}
			}
			if len(a.References) > 0 {
				fmt.Fprintf(out, "  References\n")
				for _, ref := range a.References {
					fmt.Fprintf(out, "               %s\n", ref)
				}
			}
		} else {
			// Show just the first fixed version in summary mode.
			for _, r := range a.Affected {
				if r.Fixed != "" {
					fmt.Fprintf(out, "  Fixed in   %s\n", r.Fixed)
					break
				}
			}
		}

		fmt.Fprintln(out)
	}
}

func indentBlock(s, indent string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = indent + l
	}
	return strings.Join(lines, "\n")
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func init() {
	osvCmd.Flags().StringP("package", "p", "", "Package name to look up")
	osvCmd.Flags().StringP("version", "v", "", "Filter to advisories affecting this exact version")
	osvCmd.Flags().StringP("ecosystem", "e", "", "Ecosystem to scope the search (npm, pypi, cargo, go, …)")
	osvCmd.Flags().Bool("detail", false, "Show full advisory text, affected ranges, and references")
	osvCmd.Flags().Bool("html", false, "Output as HTML")
	osvCmd.Flags().Bool("md", false, "Output as Markdown")
	osvCmd.Flags().Bool("json", false, "Output as JSON")
	osvCmd.Flags().StringP("output", "o", "", "Write report to file (format inferred from extension)")
	rootCmd.AddCommand(osvCmd)
}
