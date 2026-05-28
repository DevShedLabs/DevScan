package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type PHPDetector struct{}

func (d *PHPDetector) Name() string { return "php" }

func (d *PHPDetector) Detect() (*schema.Runtime, error) {
	path := which("php")
	if path == "" {
		return nil, nil
	}

	raw, err := execVersion("php", "--version")
	if err != nil {
		return nil, err
	}

	// "PHP 8.2.10 (cli) ..." → "8.2.10"
	version := ""
	if parts := strings.Fields(raw); len(parts) >= 2 {
		version = parts[1]
	}

	return &schema.Runtime{
		Name:    "php",
		Version: version,
		Status:  schema.StatusUnknown,
		Path:    path,
	}, nil
}
