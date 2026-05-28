package cmd

import (
	"fmt"
	"os"

	"github.com/DevShedLabs/devscan/internal/schema"
	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Suggest fix commands for vulnerabilities and outdated packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}

		suggestions := collectFixes(report)
		if len(suggestions) == 0 {
			fmt.Println("No fixes needed.")
			return nil
		}

		if dryRun {
			fmt.Println("Suggested fix commands (dry-run):")
		} else {
			fmt.Println("Suggested fix commands:")
		}

		for _, s := range suggestions {
			fmt.Printf("  %s\n", s)
		}

		if !dryRun {
			fmt.Println("\nRun the commands above manually to apply fixes.")
			fmt.Println("Use --dry-run to suppress this message.")
		}

		os.Exit(2)
		return nil
	},
}

func collectFixes(report *schema.Report) []string {
	seen := map[string]bool{}
	var out []string

	for _, v := range report.Vulnerabilities {
		if v.Fix != nil && v.Fix.Command != "" && !seen[v.Fix.Command] {
			seen[v.Fix.Command] = true
			out = append(out, fmt.Sprintf("# fix %s (%s): %s", v.Package, v.ID, v.Fix.Command))
		}
	}

	for _, o := range report.Outdated {
		cmd := upgradeCommandForOutdated(o)
		if cmd != "" && !seen[cmd] {
			seen[cmd] = true
			out = append(out, fmt.Sprintf("# update %s %s → %s: %s", o.Name, o.Current, o.Latest, cmd))
		}
	}

	return out
}

func upgradeCommandForOutdated(o schema.Outdated) string {
	switch o.Ecosystem {
	case "npm":
		return fmt.Sprintf("npm install %s@%s", o.Name, o.Latest)
	case "pypi":
		return fmt.Sprintf("pip install --upgrade %s==%s", o.Name, o.Latest)
	default:
		return ""
	}
}

func init() {
	fixCmd.Flags().Bool("dry-run", false, "Print suggested fixes without running them")
	rootCmd.AddCommand(fixCmd)
}
