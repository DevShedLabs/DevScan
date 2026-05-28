package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type PythonDetector struct{}

func (d *PythonDetector) Name() string { return "python" }

func (d *PythonDetector) Detect() (*schema.Runtime, error) {
	// prefer python3, fall back to python
	binary := "python3"
	path := which(binary)
	if path == "" {
		binary = "python"
		path = which(binary)
	}
	if path == "" {
		return nil, nil
	}

	raw, err := execVersion(binary, "--version")
	if err != nil {
		return nil, err
	}

	// "Python 3.11.4" → "3.11.4"
	version := strings.TrimPrefix(raw, "Python ")

	return &schema.Runtime{
		Name:    "python",
		Version: version,
		Status:  schema.StatusUnknown,
		Path:    path,
	}, nil
}
