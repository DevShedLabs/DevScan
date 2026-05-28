package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().String("format", "table", "Output format: table|json|compact")
	rootCmd.PersistentFlags().String("severity", "", "Filter by severity: critical|high|medium|low")
	rootCmd.PersistentFlags().String("ecosystem", "", "Filter by ecosystem: npm|pypi|gem|go")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable color output")
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
