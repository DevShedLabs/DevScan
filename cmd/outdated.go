package cmd

import (
	"os"

	"github.com/DevShedLabs/devscan/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var outdatedCmd = &cobra.Command{
	Use:   "outdated",
	Short: "Show outdated runtimes and packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}

		// Trim to outdated-relevant fields only
		report.Vulnerabilities = nil
		report.ComputeSummary()

		format := output.Format(viper.GetString("format"))
		if err := output.Render(os.Stdout, report, format); err != nil {
			return err
		}

		if len(report.Outdated) > 0 {
			os.Exit(4)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(outdatedCmd)
}
