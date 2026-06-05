package report

import (
	"io"

	"github.com/DevShedLabs/devscan/internal/keyscanner"
	"github.com/DevShedLabs/devscan/internal/schema"
)

type Format string

const (
	FormatMarkdown Format = "md"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
)

type Options struct {
	// Public strips internal details (package list, project paths, vuln install
	// paths) — suitable for committing to a public repo.
	Public bool
	// KeyFindings, if non-nil, appends a secrets section to the report.
	KeyFindings []keyscanner.Finding
}

func Render(w io.Writer, r *schema.Report, format Format, opts Options) error {
	if opts.Public {
		r = redactForPublic(r)
	}
	switch format {
	case FormatHTML:
		return renderHTML(w, r, opts.KeyFindings)
	case FormatJSON:
		return renderJSON(w, r, opts.KeyFindings)
	default:
		return renderMarkdown(w, r, opts.KeyFindings)
	}
}

// redactForPublic returns a shallow copy of the report with internal details removed.
func redactForPublic(r *schema.Report) *schema.Report {
	copy := *r
	copy.Packages = nil
	copy.Projects = nil
	// Strip filesystem paths from vulnerabilities
	vulns := make([]schema.Vulnerability, len(r.Vulnerabilities))
	for i, v := range r.Vulnerabilities {
		v.Paths = nil
		vulns[i] = v
	}
	copy.Vulnerabilities = vulns
	// Clear the scan path — internal directory
	copy.Meta.Path = ""
	return &copy
}
