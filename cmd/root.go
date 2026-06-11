package cmd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

var rootCmd = &cobra.Command{
	Use:   "devscan",
	Short: "Dev environment security and health scanner",
	Long: `devscan detects runtimes, inspects packages, and surfaces
vulnerabilities and outdated dependencies across your dev environment.`,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = buildVersion()
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().String("format", "table", "Output format: table|json|compact")
	rootCmd.PersistentFlags().String("severity", "", "Filter by severity: critical|high|medium|low")
	rootCmd.PersistentFlags().String("ecosystem", "", "Filter by ecosystem: npm|pypi|gem|go")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable color output")
	rootCmd.PersistentFlags().Bool("no-cache", false, "Bypass cache and force a fresh advisory lookup")
	rootCmd.PersistentFlags().Bool("advisories-only", false, "Match only user advisories and blocklists — skip OSV network lookup")
	rootCmd.PersistentFlags().Int("depth", 0, "Traverse subdirectories up to this depth looking for projects (0 = path only)")
	rootCmd.PersistentFlags().Bool("global", false, "Scan global packages (default)")
	rootCmd.PersistentFlags().Bool("project", false, "Scan current project directory")
	rootCmd.PersistentFlags().String("path", "", "Explicit project path to scan")

	viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))
	viper.BindPFlag("severity", rootCmd.PersistentFlags().Lookup("severity"))
	viper.BindPFlag("ecosystem", rootCmd.PersistentFlags().Lookup("ecosystem"))
}

func initConfig() {
	viper.SetConfigName(".devscan")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME")
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}
