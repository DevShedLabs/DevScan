package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/DevShedLabs/devscan/internal/schema"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

type Client struct {
	http    *http.Client
	baseURL string
}

func NewClient() *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: osvBatchURL,
	}
}

// osvEcosystem maps our ecosystem names to OSV ecosystem names.
var osvEcosystem = map[string]string{
	"npm":   "npm",
	"pypi":  "PyPI",
	"gem":   "RubyGems",
	"go":    "Go",
	"cargo": "crates.io",
}

type osvQuery struct {
	Queries []osvPackageQuery `json:"queries"`
}

type osvPackageQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
	Refs     []osvRef      `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed string `json:"fixed"`
}

type osvRef struct {
	URL string `json:"url"`
}

// QueryPackages queries OSV for vulnerabilities across a set of packages.
func (c *Client) QueryPackages(packages []schema.Package) ([]schema.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	queries := make([]osvPackageQuery, 0, len(packages))
	for _, p := range packages {
		eco, ok := osvEcosystem[p.Ecosystem]
		if !ok {
			continue
		}
		queries = append(queries, osvPackageQuery{
			Package: osvPackage{Name: p.Name, Ecosystem: eco},
			Version: p.Version,
		})
	}

	if len(queries) == 0 {
		return nil, nil
	}

	body, err := json.Marshal(osvQuery{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("advisory: marshal: %w", err)
	}

	resp, err := c.http.Post(c.baseURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("advisory: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisory: OSV returned %d", resp.StatusCode)
	}

	var batch osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, fmt.Errorf("advisory: decode: %w", err)
	}

	var vulns []schema.Vulnerability
	for i, result := range batch.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]
		for _, v := range result.Vulns {
			vuln := schema.Vulnerability{
				ID:               v.ID,
				Package:          pkg.Name,
				Ecosystem:        pkg.Ecosystem,
				InstalledVersion: pkg.Version,
				Title:            v.Summary,
				Description:      v.Details,
				Severity:         parseSeverity(v.Severity),
			}

			for _, ref := range v.Refs {
				vuln.References = append(vuln.References, ref.URL)
			}

			if fixed := extractFixed(v.Affected); fixed != "" {
				vuln.FixedIn = fixed
				vuln.Fix = &schema.Fix{
					Type:    "upgrade",
					Command: upgradeCommand(pkg, fixed),
				}
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func parseSeverity(severities []osvSeverity) schema.Severity {
	for _, s := range severities {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return cvssToSeverity(s.Score)
		}
	}
	return schema.SeverityUnknown
}

func cvssToSeverity(score string) schema.Severity {
	// CVSS scores are strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	// For now return unknown; a real implementation would parse the base score.
	_ = score
	return schema.SeverityUnknown
}

func extractFixed(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func upgradeCommand(pkg schema.Package, fixedIn string) string {
	switch pkg.Ecosystem {
	case "npm":
		return fmt.Sprintf("npm install %s@^%s", pkg.Name, fixedIn)
	case "pypi":
		return fmt.Sprintf("pip install --upgrade %s>=%s", pkg.Name, fixedIn)
	default:
		return ""
	}
}
