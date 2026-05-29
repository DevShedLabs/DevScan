package schema

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

type Status string

const (
	StatusOK       Status = "ok"
	StatusOutdated Status = "outdated"
	StatusEOL      Status = "eol"
	StatusUnknown  Status = "unknown"
)

type Meta struct {
	Version    string    `json:"version"`
	Timestamp  time.Time `json:"timestamp"`
	Target     string    `json:"target"`
	Path       string    `json:"path,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	OS         string    `json:"os,omitempty"`
	OSVersion  string    `json:"os_version,omitempty"`
	Arch       string    `json:"arch,omitempty"`
	Chip       string    `json:"chip,omitempty"`
}

type Runtime struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Latest  string `json:"latest,omitempty"`
	Status  Status `json:"status"`
	Path    string `json:"path"`
}

type PackageManager struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Global    bool   `json:"global"`
	Ecosystem string `json:"ecosystem"`
}

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Latest    string `json:"latest,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Scope     string `json:"scope"` // global | project
	Direct    bool   `json:"direct"`
	Path      string `json:"path,omitempty"`
}

type Fix struct {
	Type    string `json:"type"` // upgrade | remove | replace
	Command string `json:"command"`
}

type Vulnerability struct {
	ID               string   `json:"id"`
	Package          string   `json:"package"`
	Ecosystem        string   `json:"ecosystem"`
	InstalledVersion string   `json:"installed_version"`
	Paths            []string `json:"paths,omitempty"`
	Severity         Severity `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description,omitempty"`
	FixedIn          string   `json:"fixed_in,omitempty"`
	References       []string `json:"references,omitempty"`
	Fix              *Fix     `json:"fix,omitempty"`
}

type Outdated struct {
	Name      string   `json:"name"`
	Current   string   `json:"current"`
	Latest    string   `json:"latest"`
	Ecosystem string   `json:"ecosystem"`
	Severity  Severity `json:"severity"` // patch | minor | major (reusing type)
}

type VulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type Summary struct {
	Runtimes        int         `json:"runtimes"`
	Packages        int         `json:"packages"`
	Vulnerabilities VulnSummary `json:"vulnerabilities"`
	Outdated        int         `json:"outdated"`
}

type Report struct {
	Meta            Meta             `json:"meta"`
	System          map[string]string `json:"system"`
	Runtimes        []Runtime        `json:"runtimes"`
	PackageManagers []PackageManager `json:"package_managers"`
	Packages        []Package        `json:"packages"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
	Outdated        []Outdated       `json:"outdated"`
	Summary         Summary          `json:"summary"`
}

func (r *Report) ComputeSummary() {
	r.Summary.Runtimes = len(r.Runtimes)
	r.Summary.Packages = len(r.Packages)
	r.Summary.Outdated = len(r.Outdated)
	for _, v := range r.Vulnerabilities {
		switch v.Severity {
		case SeverityCritical:
			r.Summary.Vulnerabilities.Critical++
		case SeverityHigh:
			r.Summary.Vulnerabilities.High++
		case SeverityMedium:
			r.Summary.Vulnerabilities.Medium++
		case SeverityLow:
			r.Summary.Vulnerabilities.Low++
		default:
			r.Summary.Vulnerabilities.Unknown++
		}
	}
}
