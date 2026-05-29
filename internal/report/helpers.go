package report

import (
	"fmt"

	"github.com/DevShedLabs/devscan/internal/schema"
)

func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	secs := ms / 1000
	rem := ms % 1000
	if secs < 60 {
		return fmt.Sprintf("%d.%ds", secs, rem/100)
	}
	mins := secs / 60
	secs = secs % 60
	return fmt.Sprintf("%dm %ds", mins, secs)
}

func anyFixedIn(vulns []schema.Vulnerability) bool {
	for _, v := range vulns {
		if v.FixedIn != "" {
			return true
		}
	}
	return false
}

func anyFix(vulns []schema.Vulnerability) bool {
	for _, v := range vulns {
		if v.Fix != nil && v.Fix.Command != "" {
			return true
		}
	}
	return false
}
