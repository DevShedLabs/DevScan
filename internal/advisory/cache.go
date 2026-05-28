package advisory

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DevShedLabs/devscan/internal/schema"
)

const cacheTTL = time.Hour

type cacheEntry struct {
	CachedAt time.Time            `json:"cached_at"`
	Vulns    []schema.Vulnerability `json:"vulns"`
}

func cacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "devscan")
	return dir, os.MkdirAll(dir, 0700)
}

func cacheKey(queries []osvPackageQuery) string {
	h := sha256.New()
	for _, q := range queries {
		fmt.Fprintf(h, "%s|%s|%s\n", q.Package.Ecosystem, q.Package.Name, q.Version)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c *Client) loadCache(key string) ([]schema.Vulnerability, bool) {
	dir, err := cacheDir()
	if err != nil {
		return nil, false
	}

	data, err := os.ReadFile(filepath.Join(dir, key+".json"))
	if err != nil {
		return nil, false
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	if time.Since(entry.CachedAt) > cacheTTL {
		return nil, false
	}

	return entry.Vulns, true
}

func (c *Client) saveCache(key string, vulns []schema.Vulnerability) {
	dir, err := cacheDir()
	if err != nil {
		return
	}

	entry := cacheEntry{
		CachedAt: time.Now(),
		Vulns:    vulns,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Write to a temp file then rename for atomic replacement.
	tmp := filepath.Join(dir, key+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	os.Rename(tmp, filepath.Join(dir, key+".json"))
}
