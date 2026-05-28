package report

import (
	"encoding/json"
	"io"

	"github.com/DevShedLabs/devscan/internal/schema"
)

func renderJSON(w io.Writer, r *schema.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
