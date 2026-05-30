package advisory

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var pkgClient = &http.Client{Timeout: 8 * time.Second}

// fetchLatestPackageVersion returns the latest published version for a package
// from its ecosystem registry. Returns "" on any error so callers fall back to fixedIn.
func fetchLatestPackageVersion(ecosystem, name string) string {
	switch ecosystem {
	case "npm":
		return fetchNpmLatest(name)
	case "packagist":
		return fetchPackagistLatest(name)
	case "pypi":
		return fetchPyPILatest(name)
	case "gem":
		return fetchRubyGemsLatest(name)
	case "crates.io":
		return fetchCratesLatest(name)
	}
	return ""
}

func fetchNpmLatest(name string) string {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/latest", name)
	resp, err := pkgClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.Version
}

func fetchPackagistLatest(name string) string {
	url := fmt.Sprintf("https://repo.packagist.org/p2/%s.json", name)
	resp, err := pkgClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	if pkgs, ok := data.Packages[name]; ok && len(pkgs) > 0 {
		v := strings.TrimPrefix(pkgs[0].Version, "v")
		// Skip dev/alpha/beta/RC releases
		if !isStableVersion(v) {
			for _, p := range pkgs[1:] {
				v = strings.TrimPrefix(p.Version, "v")
				if isStableVersion(v) {
					return v
				}
			}
			return ""
		}
		return v
	}
	return ""
}

func fetchPyPILatest(name string) string {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	resp, err := pkgClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.Info.Version
}

func fetchRubyGemsLatest(name string) string {
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", name)
	resp, err := pkgClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.Version
}

func fetchCratesLatest(name string) string {
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s", name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "devscan/0.1 (https://github.com/DevShedLabs/devscan)")
	resp, err := pkgClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var data struct {
		Crate struct {
			NewestVersion string `json:"newest_version"`
		} `json:"crate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.Crate.NewestVersion
}

// isStableVersion returns false for dev/alpha/beta/RC version strings.
func isStableVersion(v string) bool {
	lower := strings.ToLower(v)
	for _, pre := range []string{"dev", "alpha", "beta", "rc", "patch"} {
		if strings.Contains(lower, pre) {
			return false
		}
	}
	return true
}
