package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type GitDetector struct{}

func (d *GitDetector) Name() string { return "git" }

func (d *GitDetector) Detect() (*schema.Runtime, error) {
	path := which("git")
	if path == "" {
		return nil, nil
	}

	raw, err := execVersion("git", "--version")
	if err != nil {
		return nil, err
	}

	// "git version 2.39.0" → "2.39.0"
	version := strings.TrimPrefix(raw, "git version ")

	return &schema.Runtime{
		Name:    "git",
		Version: version,
		Status:  schema.StatusUnknown,
		Path:    path,
	}, nil
}
