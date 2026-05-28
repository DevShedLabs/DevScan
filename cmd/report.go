package cmd

import (
	"fmt"
	"os"

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

		// Default to markdown if nothing specified
		format := report.FormatMarkdown
		switch {
		case html:
			format = report.FormatHTML
		case jsonFmt:
			format = report.FormatJSON
		case md:
			format = report.FormatMarkdown
		}

		opts := scanOptsFromCmd(cmd)
		r, err := runFullScan(opts)
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

		if err := report.Render(out, r, format); err != nil {
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
	rootCmd.AddCommand(reportCmd)
}
