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

	// Tally severities for the summary cards.
	counts := map[string]int{}
	for _, a := range advisories {
		counts[strings.ToLower(a.Severity)]++
	}

	p(`<!DOCTYPE html>`)
	p(`<html lang="en">`)
	p(`<head>`)
	p(`<meta charset="UTF-8">`)
	p(`<meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	p(`<title>OSV Advisory Search — DevScan</title>`)
	p(`<style>%s%s</style>`, htmlCSS(), osvExtraCSS())
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

	// Summary cards — only show severities that have results.
	p(`<section class="summary">`)
	for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
		n := counts[sev]
		if n == 0 {
			continue
		}
		p(`  <div class="card %s"><div class="card-value">%d</div><div class="card-label">%s</div></div>`,
			sev, n, strings.ToUpper(sev))
	}
	p(`</section>`)

	p(`<main>`)
	p(`<section>`)
	p(`  <h2 class="section-heading">Advisories<span class="heading-count">%d</span></h2>`, len(advisories))

	for _, a := range advisories {
		sev := strings.ToLower(a.Severity)

		p(`  <div class="osv-card osv-sev-%s">`, html.EscapeString(sev))

		// Card header: ID on the left, severity badge on the right.
		p(`    <div class="osv-card-header">`)
		p(`      <a class="osv-id" href="https://osv.dev/vulnerability/%s" target="_blank" rel="noopener">%s</a>`,
			html.EscapeString(a.ID), html.EscapeString(a.ID))
		p(`      <span class="osv-badge osv-badge-%s">%s</span>`, html.EscapeString(sev), html.EscapeString(strings.ToUpper(sev)))
		p(`    </div>`)

		// Card body.
		p(`    <div class="osv-card-body">`)

		if a.Summary != "" {
			p(`      <div class="osv-summary">%s</div>`, html.EscapeString(a.Summary))
		}

		if a.Package != "" {
			p(`      <div class="osv-meta-row">`)
			p(`        <span class="osv-meta-label">Package</span>`)
			p(`        <span><strong>%s</strong>`, html.EscapeString(a.Package))
			if a.Ecosystem != "" {
				p(`        <span class="ecosystem">%s</span>`, html.EscapeString(a.Ecosystem))
			}
			p(`        </span>`)
			p(`      </div>`)
		}

		// Affected version ranges.
		var ranges []advisory.OSVAffectedRange
		for _, r := range a.Affected {
			if r.Fixed != "" {
				ranges = append(ranges, r)
				if !detail {
					break
				}
			}
		}
		if len(ranges) > 0 {
			p(`      <div class="osv-meta-row">`)
			p(`        <span class="osv-meta-label">Affected</span>`)
			p(`        <span class="osv-ranges">`)
			for _, r := range ranges {
				intro := r.Introduced
				if intro == "" {
					intro = "0"
				}
				p(`          <span class="osv-range">&gt;= <code>%s</code> &rarr; fixed in <code class="fix-version">%s</code></span>`,
					html.EscapeString(intro), html.EscapeString(r.Fixed))
			}
			p(`        </span>`)
			p(`      </div>`)
		}

		if detail && a.Details != "" {
			p(`      <div class="osv-details">%s</div>`, html.EscapeString(a.Details))
		}

		if detail && len(a.References) > 0 {
			p(`      <div class="osv-meta-row osv-refs-row">`)
			p(`        <span class="osv-meta-label">References</span>`)
			p(`        <ul class="osv-refs">`)
			for _, ref := range a.References {
				p(`          <li><a href="%s" target="_blank" rel="noopener">%s</a></li>`,
					html.EscapeString(ref), html.EscapeString(ref))
			}
			p(`        </ul>`)
			p(`      </div>`)
		}

		p(`    </div>`) // osv-card-body
		p(`  </div>`)   // osv-card
	}

	p(`</section>`)
	p(`</main>`)

	p(`<footer>`)
	p(`  <p>Generated by <a href="https://github.com/DevShedLabs/devscan">devscan</a> · %s</p>`, time.Now().Format("2006"))
	p(`</footer>`)
	p(`</body>`)
	p(`</html>`)

	return nil
}

func osvExtraCSS() string {
	return `
/* OSV advisory cards */
.osv-card {
  background: #fff;
  border: 1px solid #e5e7eb;
  border-left: 4px solid #e5e7eb;
  border-radius: 8px;
  margin-bottom: 16px;
  overflow: hidden;
}

.osv-sev-critical { border-left-color: #dc2626; }
.osv-sev-high     { border-left-color: #ea580c; }
.osv-sev-medium   { border-left-color: #ca8a04; }
.osv-sev-low      { border-left-color: #16a34a; }
.osv-sev-unknown  { border-left-color: #9ca3af; }

.osv-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
}

.osv-id {
  font-family: "SF Mono", "Fira Code", monospace;
  font-size: 13px;
  font-weight: 600;
  color: #111;
  text-decoration: none;
}
.osv-id:hover { color: #2563eb; text-decoration: underline; }

.osv-badge {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 3px 10px;
  border-radius: 99px;
  color: #fff;
}
.osv-badge-critical { background: #dc2626; }
.osv-badge-high     { background: #ea580c; }
.osv-badge-medium   { background: #ca8a04; }
.osv-badge-low      { background: #16a34a; }
.osv-badge-unknown  { background: #9ca3af; }

.osv-card-body {
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.osv-summary {
  font-size: 14px;
  font-weight: 500;
  color: #111;
  line-height: 1.5;
}

.osv-meta-row {
  display: flex;
  align-items: baseline;
  gap: 12px;
  font-size: 13px;
  color: #374151;
}

.osv-meta-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #9ca3af;
  min-width: 80px;
  flex-shrink: 0;
}

.osv-ranges {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.osv-range {
  font-size: 12px;
  color: #374151;
  background: #f3f4f6;
  padding: 3px 10px;
  border-radius: 6px;
}

code.fix-version {
  background: #dcfce7;
  color: #15803d;
}

.osv-details {
  font-size: 13px;
  color: #4b5563;
  line-height: 1.6;
  white-space: pre-wrap;
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 6px;
  padding: 12px 14px;
}

.osv-refs-row { align-items: flex-start; }

.osv-refs {
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
}

.osv-refs a { color: #2563eb; word-break: break-all; }
`
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
