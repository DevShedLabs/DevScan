package cmd

import (
	"os"

	"github.com/DevShedLabs/devscan/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List detected runtimes and installed packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}

		// Trim to inventory fields only
		report.Vulnerabilities = nil
		report.Outdated = nil
		report.ComputeSummary()

		format := output.Format(viper.GetString("format"))
		return output.Render(os.Stdout, report, format)
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
