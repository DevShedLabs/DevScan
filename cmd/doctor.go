package cmd

import (
	"os"

	"github.com/DevShedLabs/devscan/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Full system scan: runtimes, packages, vulnerabilities, and outdated deps",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}
		format := output.Format(viper.GetString("format"))
		return output.Render(os.Stdout, report, format)
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
