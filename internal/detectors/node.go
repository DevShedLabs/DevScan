package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type NodeDetector struct{}

func (d *NodeDetector) Name() string { return "node" }

func (d *NodeDetector) Detect() (*schema.Runtime, error) {
	path := which("node")
	if path == "" {
		return nil, nil
	}

	raw, err := execVersion("node", "--version")
	if err != nil {
		return nil, err
	}

	version := strings.TrimPrefix(raw, "v")

	return &schema.Runtime{
		Name:    "node",
		Version: version,
		Status:  schema.StatusUnknown, // resolved by advisory layer
		Path:    path,
	}, nil
}
