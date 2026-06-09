package cmd

import (
	"fmt"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/spf13/cobra"
)

var updateDBCmd = &cobra.Command{
	Use:   "update-db",
	Short: "Fetch the latest blocklist databases and recompile",
	Long: `Downloads the latest malware databases from Aikido's open-source
threat intelligence feed (malware-list.aikido.dev) and saves them to
~/.devscan/resources/, then recompiles the index.

Sources fetched:
  malware_predictions.json  — npm malware database (Aikido Intel)
  malware_pypi.json         — PyPI malware database (Aikido Intel)

Run this periodically to keep your blocklists current. It is also run
automatically by 'devscan update'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fetched, err := advisory.UpdateDB(func(msg string) { fmt.Println(msg) })
		if err != nil {
			return fmt.Errorf("update-db failed: %w", err)
		}
		fmt.Printf("Fetched %d sources.\n\n", fetched)

		fmt.Println("Compiling index...")
		outPath, count, err := advisory.CompileBlocklists()
		if err != nil {
			return fmt.Errorf("compile failed: %w", err)
		}
		fmt.Printf("Compiled %d entries → %s\n", count, outPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateDBCmd)
}
