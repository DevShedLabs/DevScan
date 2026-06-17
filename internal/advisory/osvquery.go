package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// advisoryIDRe matches well-known advisory ID prefixes with only safe characters.
var advisoryIDRe = regexp.MustCompile(`(?i)^(CVE|GHSA|OSV|RUSTSEC|GO|PYSEC|NPM|SNYK)-[A-Za-z0-9\-]+$`)

const osvQueryURL = "https://api.osv.dev/v1/query"

// OSVAdvisory is a self-contained advisory result returned by the OSV search
// functions. It is richer than schema.Vulnerability because it includes the
// full affected version ranges and all references.
type OSVAdvisory struct {
	ID          string
	Severity    string
	Summary     string
	Details     string
	Ecosystem   string
	Package     string
	Affected    []OSVAffectedRange
	References  []string
	PublishedAt string
}

// OSVAffectedRange describes one affected version range for a package.
type OSVAffectedRange struct {
	Introduced string
	Fixed      string
}

// SearchByPackage queries OSV for all advisories affecting the named package.
// If ecosystem is empty, all ecosystems defined in osvEcosystem are tried and
// results are merged. If version is non-empty, only advisories affecting that
// exact version are returned.
func SearchByPackage(name, ecosystem, version string, noCache bool) ([]OSVAdvisory, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	if ecosystem != "" {
		return queryOSVPackage(client, name, ecosystem, version)
	}

	// Fan out across all known ecosystems and merge.
	var all []OSVAdvisory
	seen := map[string]bool{}
	for _, eco := range osvEcosystem {
		got, err := queryOSVPackage(client, name, eco, version)
		if err != nil {
			continue
		}
		for _, a := range got {
			if !seen[a.ID] {
				seen[a.ID] = true
				all = append(all, a)
			}
		}
	}
	return all, nil
}

// LookupID fetches a single advisory by its OSV/CVE/GHSA ID.
func LookupID(id string) (*OSVAdvisory, error) {
	if !advisoryIDRe.MatchString(id) {
		return nil, fmt.Errorf("invalid advisory ID %q", id)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(osvVulnURL + id)
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("advisory %q not found", id)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: server returned %d", resp.StatusCode)
	}

	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("osv: decode: %w", err)
	}
	a := vulnToAdvisory(v, "", "")
	return &a, nil
}

// SearchFreeText queries OSV for each known ecosystem using the term as a
// package name, then filters results so that the term appears somewhere in the
// advisory ID, summary, details, or package name.
func SearchFreeText(term, ecosystem string) ([]OSVAdvisory, error) {
	results, err := SearchByPackage(term, ecosystem, "", false)
	if err != nil {
		return nil, err
	}

	lower := strings.ToLower(term)
	var matched []OSVAdvisory
	for _, a := range results {
		if strings.Contains(strings.ToLower(a.ID), lower) ||
			strings.Contains(strings.ToLower(a.Summary), lower) ||
			strings.Contains(strings.ToLower(a.Details), lower) ||
			strings.Contains(strings.ToLower(a.Package), lower) {
			matched = append(matched, a)
		}
	}
	return matched, nil
}

func queryOSVPackage(client *http.Client, name, ecosystem, version string) ([]OSVAdvisory, error) {
	type reqPkg struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type req struct {
		Package reqPkg `json:"package"`
		Version string `json:"version,omitempty"`
	}

	body, err := json.Marshal(req{
		Package: reqPkg{Name: name, Ecosystem: ecosystem},
		Version: version,
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(osvQueryURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: server returned %d", resp.StatusCode)
	}

	var result osvResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv: decode: %w", err)
	}

	advisories := make([]OSVAdvisory, 0, len(result.Vulns))
	for _, v := range result.Vulns {
		advisories = append(advisories, vulnToAdvisory(v, name, ecosystem))
	}
	return advisories, nil
}

func vulnToAdvisory(v osvVuln, pkg, ecosystem string) OSVAdvisory {
	a := OSVAdvisory{
		ID:        v.ID,
		Summary:   v.Summary,
		Details:   v.Details,
		Severity:  string(parseSeverity(v.Severity)),
		Package:   pkg,
		Ecosystem: ecosystem,
	}

	for _, ref := range v.Refs {
		a.References = append(a.References, ref.URL)
	}

	// Collect affected package names and version ranges.
	for _, affected := range v.Affected {
		for _, r := range affected.Ranges {
			var intro, fixed string
			for _, e := range r.Events {
				if e.Introduced != "" {
					intro = e.Introduced
				}
				if e.Fixed != "" {
					fixed = e.Fixed
				}
			}
			if intro != "" || fixed != "" {
				a.Affected = append(a.Affected, OSVAffectedRange{
					Introduced: intro,
					Fixed:      fixed,
				})
			}
		}
	}

	return a
}
