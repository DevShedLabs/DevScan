package cmd

import (
	"fmt"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/spf13/cobra"
)

var compileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Compile blocklist resources into a single index",
	Long: `Merges all *.csv and *.json blocklist files from ~/.devscan/resources/
into a single compiled index at ~/.devscan/devscan.json.

Scans use the compiled index automatically when it exists, which is much
faster than re-parsing source files on every run — especially for large
databases like the Aikido malware list.

Run this command after adding, updating, or removing any source files.

Source file formats supported:
  CSV   Ecosystem,Namespace,Name,Version,...  (miasma-style)
  JSON  [{package_name,version,reason}]       (Aikido-style, npm-only)
  JSON  [{ecosystem,name,version,reason}]     (generic)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dirs := advisory.ResourceDirs()
		fmt.Println("Searching for blocklist sources in:")
		for _, d := range dirs {
			fmt.Println("  " + d)
		}
		fmt.Println()

		outPath, count, err := advisory.CompileBlocklists()
		if err != nil {
			return fmt.Errorf("compile failed: %w", err)
		}

		if count == 0 {
			fmt.Println("No blocklist entries found. Drop *.csv or *.json files into ~/.devscan/resources/ and try again.")
			return nil
		}

		fmt.Printf("Compiled %d entries → %s\n", count, outPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(compileCmd)
}
