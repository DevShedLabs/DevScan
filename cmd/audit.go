package cmd

import (
	"os"

	"github.com/DevShedLabs/devscan/internal/output"
	"github.com/DevShedLabs/devscan/internal/schema"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Vulnerability scan only",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}

		// Filter by severity if requested
		sev := viper.GetString("severity")
		if sev != "" {
			report.Vulnerabilities = filterBySeverity(report.Vulnerabilities, schema.Severity(sev))
		}

		// Trim report to vuln-relevant fields
		report.Runtimes = nil
		report.Outdated = nil
		report.ComputeSummary()

		format := output.Format(viper.GetString("format"))
		exitCode := vulnExitCode(report.Vulnerabilities)
		if err := output.Render(os.Stdout, report, format); err != nil {
			return err
		}
		os.Exit(exitCode)
		return nil
	},
}

func filterBySeverity(vulns []schema.Vulnerability, min schema.Severity) []schema.Vulnerability {
	order := map[schema.Severity]int{
		schema.SeverityCritical: 4,
		schema.SeverityHigh:     3,
		schema.SeverityMedium:   2,
		schema.SeverityLow:      1,
		schema.SeverityUnknown:  0,
	}
	minRank := order[min]
	var out []schema.Vulnerability
	for _, v := range vulns {
		if order[v.Severity] >= minRank {
			out = append(out, v)
		}
	}
	return out
}

func vulnExitCode(vulns []schema.Vulnerability) int {
	hasCritical := false
	for _, v := range vulns {
		if v.Severity == schema.SeverityCritical {
			hasCritical = true
		}
	}
	if hasCritical {
		return 3
	}
	if len(vulns) > 0 {
		return 2
	}
	return 0
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
