package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/keyscanner"
	"github.com/DevShedLabs/devscan/internal/report"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a full scan report in the specified format",
	Example: `  devscan report --md
  devscan report --html
  devscan report --json
  devscan report --html --output report.html`,
	RunE: func(cmd *cobra.Command, args []string) error {
		html, _ := cmd.Flags().GetBool("html")
		md, _ := cmd.Flags().GetBool("md")
		jsonFmt, _ := cmd.Flags().GetBool("json")
		outputFile, _ := cmd.Flags().GetString("output")
		public, _ := cmd.Flags().GetBool("public")

		// Infer format from output file extension if no flag given.
		format := report.FormatMarkdown
		switch {
		case html:
			format = report.FormatHTML
		case jsonFmt:
			format = report.FormatJSON
		case md:
			format = report.FormatMarkdown
		case outputFile != "":
			switch strings.ToLower(filepath.Ext(outputFile)) {
			case ".html", ".htm":
				format = report.FormatHTML
			case ".json":
				format = report.FormatJSON
			case ".md", ".markdown":
				format = report.FormatMarkdown
			}
		}

		includeKeys, _ := cmd.Flags().GetBool("include-keys")

		opts := scanOptsFromCmd(cmd)
		r, err := runFullScan(opts)
		if err != nil {
			return err
		}

		var keyFindings []keyscanner.Finding
		if includeKeys {
			scanPath := opts.path
			if scanPath == "" {
				scanPath, _ = os.Getwd()
			}
			keyFindings, err = keyscanner.Scan(scanPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: key scan failed: %v\n", err)
			}
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

		if err := report.Render(out, r, format, report.Options{Public: public, KeyFindings: keyFindings}); err != nil {
			return err
		}

		if outputFile != "" {
			fmt.Fprintf(os.Stderr, "Report written to %s\n", outputFile)
		}
		return nil
	},
}

func init() {
	reportCmd.Flags().Bool("html", false, "Generate HTML report")
	reportCmd.Flags().Bool("md", false, "Generate Markdown report")
	reportCmd.Flags().Bool("json", false, "Generate JSON report")
	reportCmd.Flags().StringP("output", "o", "", "Write report to file instead of stdout")
	reportCmd.Flags().Bool("public", false, "Strip internal paths and package inventory for public sharing")
	reportCmd.Flags().Bool("include-keys", false, "Run keyscan and include exposed secrets in the report")
	rootCmd.AddCommand(reportCmd)
}
