package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type RustDetector struct{}

func (d *RustDetector) Name() string { return "rust" }

func (d *RustDetector) Detect() (*schema.Runtime, error) {
	path := which("rustc")
	if path == "" {
		return nil, nil
	}

	raw, err := execVersion("rustc", "--version")
	if err != nil {
		return nil, err
	}

	// "rustc 1.78.0 (9b00956e5 2024-04-29)" → "1.78.0"
	version := ""
	if parts := strings.Fields(raw); len(parts) >= 2 {
		version = parts[1]
	}

	return &schema.Runtime{
		Name:    "rust",
		Version: version,
		Status:  schema.StatusUnknown,
		Path:    path,
	}, nil
}
