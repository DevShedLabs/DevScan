package report

import (
	"io"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type Format string

const (
	FormatMarkdown Format = "md"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
)

func Render(w io.Writer, r *schema.Report, format Format) error {
	switch format {
	case FormatHTML:
		return renderHTML(w, r)
	case FormatJSON:
		return renderJSON(w, r)
	default:
		return renderMarkdown(w, r)
	}
}
