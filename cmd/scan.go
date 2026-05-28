package cmd

import (
	"os"

	"github.com/DevShedLabs/devscan/internal/output"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Raw detection only: runtimes and packages (no vuln intelligence)",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}
		// scan always outputs JSON for piping
		return output.Render(os.Stdout, report, output.FormatJSON)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
