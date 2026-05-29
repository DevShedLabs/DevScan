package detectors

import (
	"github.com/DevShedLabs/devscan/internal/schema"
)

type BunDetector struct{}

func (d *BunDetector) Name() string { return "bun" }

func (d *BunDetector) Detect() (*schema.Runtime, error) {
	ver, err := execVersion("bun", "--version")
	if err != nil {
		return nil, err
	}
	return &schema.Runtime{
		Name:    "bun",
		Version: ver,
		Path:    which("bun"),
		Status:  schema.StatusUnknown,
	}, nil
}
