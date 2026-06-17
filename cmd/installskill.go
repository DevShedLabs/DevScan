package cmd

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

//go:embed skills/run-devscan/*
var embeddedSkills embed.FS

var installSkillCmd = &cobra.Command{
	Use:   "install-skill",
	Short: "Install the devscan Claude skill into ~/.claude/skills/",
	Long: `Copies the devscan Claude Code skill into ~/.claude/skills/run-devscan/
so that any AI agent can run devscan against any project.

After installation, Claude Code will offer /run-devscan as a skill in
every project.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not determine home directory: %w", err)
		}

		dest := filepath.Join(home, ".claude", "skills", "run-devscan")
		if err := os.MkdirAll(dest, 0755); err != nil {
			return fmt.Errorf("could not create skill directory: %w", err)
		}

		err = fs.WalkDir(embeddedSkills, "skills/run-devscan", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel("skills/run-devscan", path)
			target := filepath.Join(dest, rel)

			if d.IsDir() {
				return os.MkdirAll(target, 0755)
			}

			data, err := embeddedSkills.ReadFile(path)
			if err != nil {
				return err
			}

			mode := fs.FileMode(0644)
			if filepath.Ext(path) == ".sh" {
				mode = 0755
			}
			return os.WriteFile(target, data, mode)
		})
		if err != nil {
			return fmt.Errorf("could not install skill files: %w", err)
		}

		fmt.Printf("Installed devscan skill to %s\n", dest)
		fmt.Println("Claude Code will now offer /run-devscan in every project.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(installSkillCmd)
}
