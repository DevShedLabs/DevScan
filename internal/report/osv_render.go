package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/DevShedLabs/devscan/internal/advisory"
)

// ── JSON ─────────────────────────────────────────────────────────────────────

func renderOSVJSON(w io.Writer, advisories []advisory.OSVAdvisory, detail bool) error {
	if !detail {
		type summary struct {
			ID        string `json:"id"`
			Severity  string `json:"severity"`
			Summary   string `json:"summary"`
			Package   string `json:"package,omitempty"`
			Ecosystem string `json:"ecosystem,omitempty"`
			FixedIn   string `json:"fixed_in,omitempty"`
		}
		out := make([]summary, 0, len(advisories))
		for _, a := range advisories {
			s := summary{
				ID:        a.ID,
				Severity:  a.Severity,
				Summary:   a.Summary,
				Package:   a.Package,
				Ecosystem: a.Ecosystem,
			}
			for _, r := range a.Affected {
				if r.Fixed != "" {
					s.FixedIn = r.Fixed
					break
				}
			}
			out = append(out, s)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(advisories)
}

// ── Markdown ──────────────────────────────────────────────────────────────────

func renderOSVMarkdown(w io.Writer, advisories []advisory.OSVAdvisory, detail bool) error {
	p := func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	p("# OSV Advisory Search Results")
	p("")
	p("**Generated:** %s  ", time.Now().Format("2006-01-02 15:04:05 MST"))
	p("**Results:** %d advisor%s  ", len(advisories), pluralYmd(len(advisories)))
	p("")

	for _, a := range advisories {
		p("---")
		p("")
		p("## %s", a.ID)
		p("")
		p("**Severity:** %s  ", strings.ToUpper(a.Severity))
		if a.Package != "" {
			if a.Ecosystem != "" {
				p("**Package:** %s (%s)  ", a.Package, a.Ecosystem)
			} else {
				p("**Package:** %s  ", a.Package)
			}
		}
		if a.Summary != "" {
			p("**Summary:** %s  ", a.Summary)
		}

		for _, r := range a.Affected {
			if r.Fixed != "" {
				intro := r.Introduced
				if intro == "" {
					intro = "0"
				}
				p("**Affected:** >= %s, fixed in `%s`  ", intro, r.Fixed)
			}
		}

		if detail && a.Details != "" {
			p("")
			p("%s", a.Details)
		}

		if detail && len(a.References) > 0 {
			p("")
			p("**References:**")
			for _, ref := range a.References {
				p("- %s", ref)
			}
		}
		p("")
	}

	return nil
}

// ── HTML ──────────────────────────────────────────────────────────────────────

func renderOSVHTML(w io.Writer, advisories []advisory.OSVAdvisory, detail bool) error {
	p := func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	p(`<!DOCTYPE html>`)
	p(`<html lang="en">`)
	p(`<head>`)
	p(`<meta charset="UTF-8">`)
	p(`<meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	p(`<title>OSV Advisory Search — DevScan</title>`)
	p(`<style>%s</style>`, htmlCSS())
	p(`</head>`)
	p(`<body>`)

	p(`<header>`)
	p(`  <div class="logo">DevScan</div>`)
	p(`  <div class="meta">`)
	p(`    <span>OSV Advisory Search</span>`)
	p(`    <span>%s</span>`, time.Now().Format("2 Jan 2006, 15:04 MST"))
	p(`    <span>%d result%s</span>`, len(advisories), pluralShtml(len(advisories)))
	p(`  </div>`)
	p(`</header>`)

	p(`<main>`)
	p(`<section class="vuln-list">`)

	for _, a := range advisories {
		sev := strings.ToLower(a.Severity)
		p(`<div class="vuln-item sev-%s">`, html.EscapeString(sev))
		p(`  <div class="vuln-header">`)
		p(`    <span class="vuln-id">%s</span>`, html.EscapeString(a.ID))
		p(`    <span class="badge sev-%s">%s</span>`, html.EscapeString(sev), html.EscapeString(strings.ToUpper(sev)))
		p(`  </div>`)

		if a.Package != "" {
			if a.Ecosystem != "" {
				p(`  <div class="vuln-pkg"><strong>%s</strong> <span class="ecosystem">%s</span></div>`,
					html.EscapeString(a.Package), html.EscapeString(a.Ecosystem))
			} else {
				p(`  <div class="vuln-pkg"><strong>%s</strong></div>`, html.EscapeString(a.Package))
			}
		}

		if a.Summary != "" {
			p(`  <div class="vuln-title">%s</div>`, html.EscapeString(a.Summary))
		}

		for _, r := range a.Affected {
			if r.Fixed != "" {
				intro := r.Introduced
				if intro == "" {
					intro = "0"
				}
				p(`  <div class="fix-cmd">Fixed in <code>%s</code> (affected &gt;= %s)</div>`,
					html.EscapeString(r.Fixed), html.EscapeString(intro))
				if !detail {
					break
				}
			}
		}

		if detail && a.Details != "" {
			p(`  <div class="vuln-desc">%s</div>`, html.EscapeString(a.Details))
		}

		if detail && len(a.References) > 0 {
			p(`  <div class="vuln-refs"><strong>References</strong><ul>`)
			for _, ref := range a.References {
				p(`    <li><a href="%s" target="_blank" rel="noopener">%s</a></li>`,
					html.EscapeString(ref), html.EscapeString(ref))
			}
			p(`  </ul></div>`)
		}

		p(`</div>`)
	}

	p(`</section>`)
	p(`</main>`)
	p(`</body>`)
	p(`</html>`)

	return nil
}

func pluralYmd(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func pluralShtml(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
