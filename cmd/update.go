package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update devscan to the latest release",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Updating devscan...")
		out, err := exec.Command("go", "install", "github.com/DevShedLabs/devscan@latest").CombinedOutput()
		if err != nil {
			return fmt.Errorf("update failed: %w\n%s", err, string(out))
		}
		fmt.Println("Done. Run `devscan --version` to confirm.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
