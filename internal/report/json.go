package report

import (
	"encoding/json"
	"io"

	"github.com/DevShedLabs/devscan/internal/keyscanner"
	"github.com/DevShedLabs/devscan/internal/schema"
)

func renderJSON(w io.Writer, r *schema.Report, keys []keyscanner.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(keys) == 0 {
		return enc.Encode(r)
	}
	return enc.Encode(struct {
		*schema.Report
		KeyFindings []keyscanner.Finding `json:"key_findings"`
	}{r, keys})
}
