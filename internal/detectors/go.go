package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type GoDetector struct{}

func (d *GoDetector) Name() string { return "go" }

func (d *GoDetector) Detect() (*schema.Runtime, error) {
	path := which("go")
	if path == "" {
		return nil, nil
	}

	raw, err := execVersion("go", "version")
	if err != nil {
		return nil, err
	}

	// "go version go1.22.3 darwin/arm64" → "1.22.3"
	version := ""
	for _, part := range strings.Fields(raw) {
		if strings.HasPrefix(part, "go1") {
			version = strings.TrimPrefix(part, "go")
			break
		}
	}

	return &schema.Runtime{
		Name:    "go",
		Version: version,
		Status:  schema.StatusUnknown,
		Path:    path,
	}, nil
}
