package advisory

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

// CompiledIndexName is the filename written by CompileBlocklists and given
// priority over raw source files during matching.
const CompiledIndexName = "devscan.json"

// blocklistEntry holds one normalised record from any blocklist source.
type blocklistEntry struct {
	ecosystem string   // normalised to lowercase (npm, pypi, …)
	name      string
	version   string   // empty means "any version"
	reason    string   // e.g. MALWARE, TELEMETRY
	sources   []string // filenames this entry was seen in
}

// CompiledEntry is the on-disk schema for a compiled blocklist entry.
// It is also the generic JSON shape accepted by parseGenericJSON.
type CompiledEntry struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Sources   []string `json:"sources,omitempty"`
}

// devscanHome returns ~/.devscan, creating it if needed.
func devscanHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".devscan")
	return dir, os.MkdirAll(dir, 0o755)
}

// ResourceDirs returns the directories that are searched for raw blocklist
// source files (*.csv, *.json). Earlier entries take priority.
//
// Priority:
//  1. ~/.devscan/resources/   — primary user location
//  2. <executable dir>/resources/ — bundled defaults
//  3. <cwd>/resources/            — dev convenience
func ResourceDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".devscan", "resources"))
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "resources"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "resources"))
	}
	return dirs
}

// compiledIndexPath returns ~/.devscan/devscan.json.
func compiledIndexPath() (string, error) {
	dir, err := devscanHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, CompiledIndexName), nil
}

// loadBlocklists reads blocklist entries for use during scanning.
//
// If a compiled index (~/.devscan/devscan.json) exists it is used exclusively
// — raw source files are skipped. Run `devscan compile` to rebuild it after
// adding or updating source files.
func loadBlocklists() ([]blocklistEntry, error) {
	if path, err := compiledIndexPath(); err == nil {
		if _, err := os.Stat(path); err == nil {
			return parseCompiledIndex(path)
		}
	}
	return loadRawBlocklists()
}

// loadRawBlocklists parses all raw *.csv and *.json source files from
// ResourceDirs(), skipping any file named CompiledIndexName.
func loadRawBlocklists() ([]blocklistEntry, error) {
	seen := map[string]bool{}
	var entries []blocklistEntry

	for _, dir := range ResourceDirs() {
		for _, pattern := range []string{"*.csv", "*.json"} {
			files, _ := filepath.Glob(filepath.Join(dir, pattern))
			for _, f := range files {
				if filepath.Base(f) == CompiledIndexName {
					continue
				}
				real, err := filepath.EvalSymlinks(f)
				if err != nil {
					real = f
				}
				if seen[real] {
					continue
				}
				seen[real] = true

				var got []blocklistEntry
				switch strings.ToLower(filepath.Ext(f)) {
				case ".csv":
					got, err = parseBlocklistCSV(f)
				case ".json":
					got, err = parseBlocklistJSON(f)
				}
				if err == nil {
					entries = append(entries, got...)
				}
			}
		}
	}
	return entries, nil
}

// parseCompiledIndex reads a compiled devscan.json index.
func parseCompiledIndex(path string) ([]blocklistEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []CompiledEntry
	if err := json.NewDecoder(f).Decode(&records); err != nil {
		return nil, err
	}

	entries := make([]blocklistEntry, 0, len(records))
	for _, r := range records {
		if r.Name == "" {
			continue
		}
		entries = append(entries, blocklistEntry{
			ecosystem: strings.ToLower(r.Ecosystem),
			name:      r.Name,
			version:   r.Version,
			reason:    r.Reason,
			sources:   r.Sources,
		})
	}
	return entries, nil
}

// parseBlocklistCSV handles CSVs with a header row.
// Required columns: Name. Optional: Ecosystem, Namespace, Version.
//
// Expected header (miasma-style):
//
//	Ecosystem,Namespace,Name,Version,Artifact,Published,Detected
func parseBlocklistCSV(path string) ([]blocklistEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	r.ReuseRecord = true

	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}

	nameCol, hasName := col["name"]
	if !hasName {
		return nil, nil
	}
	ecosystemCol, hasEco := col["ecosystem"]
	namespaceCol, hasNS := col["namespace"]
	versionCol, hasVer := col["version"]

	source := filepath.Base(path)
	var entries []blocklistEntry

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		get := func(idx int, ok bool) string {
			if !ok || idx >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[idx])
		}

		name := get(nameCol, hasName)
		if name == "" {
			continue
		}
		if ns := get(namespaceCol, hasNS); ns != "" {
			name = "@" + strings.TrimPrefix(ns, "@") + "/" + name
		}

		entries = append(entries, blocklistEntry{
			ecosystem: strings.ToLower(get(ecosystemCol, hasEco)),
			name:      name,
			version:   get(versionCol, hasVer),
			sources:   []string{source},
		})
	}
	return entries, nil
}

// parseBlocklistJSON handles two JSON shapes:
//
// Shape A — generic (ecosystem present):
//
//	[{"ecosystem":"npm","name":"evil-pkg","version":"1.0.0"}]
//
// Shape B — Aikido-style JS-only (no ecosystem field):
//
//	[{"package_name":"evil-pkg","version":"1.0.0","reason":"MALWARE"}]
func parseBlocklistJSON(path string) ([]blocklistEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var raw []json.RawMessage
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw[0], &probe); err != nil {
		return nil, err
	}

	source := filepath.Base(path)
	_, hasPackageName := probe["package_name"]
	if hasPackageName {
		return parseAikidoJSON(raw, source)
	}
	return parseGenericJSON(raw, source)
}

func parseGenericJSON(raw []json.RawMessage, source string) ([]blocklistEntry, error) {
	type record struct {
		Ecosystem string   `json:"ecosystem"`
		Name      string   `json:"name"`
		Version   string   `json:"version"`
		Reason    string   `json:"reason"`
		Sources   []string `json:"sources"`
	}

	var entries []blocklistEntry
	for _, r := range raw {
		var rec record
		if err := json.Unmarshal(r, &rec); err != nil {
			continue
		}
		if rec.Name == "" {
			continue
		}
		sources := rec.Sources
		if len(sources) == 0 {
			sources = []string{source}
		}
		entries = append(entries, blocklistEntry{
			ecosystem: strings.ToLower(rec.Ecosystem),
			name:      rec.Name,
			version:   rec.Version,
			reason:    rec.Reason,
			sources:   sources,
		})
	}
	return entries, nil
}

func parseAikidoJSON(raw []json.RawMessage, source string) ([]blocklistEntry, error) {
	type record struct {
		PackageName string `json:"package_name"`
		Version     string `json:"version"`
		Reason      string `json:"reason"`
	}

	var entries []blocklistEntry
	for _, r := range raw {
		var rec record
		if err := json.Unmarshal(r, &rec); err != nil {
			continue
		}
		if rec.PackageName == "" {
			continue
		}
		entries = append(entries, blocklistEntry{
			ecosystem: "npm",
			name:      rec.PackageName,
			version:   rec.Version,
			reason:    rec.Reason,
			sources:   []string{source},
		})
	}
	return entries, nil
}

// CompileBlocklists merges all raw source files into a single compiled index
// at compiledIndexPath() and returns a summary of what was written.
// It returns the output path and total entry count.
func CompileBlocklists() (outPath string, count int, err error) {
	entries, err := loadRawBlocklists()
	if err != nil {
		return "", 0, err
	}

	// Merge entries with identical ecosystem+name+version, collecting all
	// sources and reasons.
	type key struct{ eco, name, ver string }
	type merged struct {
		sources map[string]bool
		reasons map[string]bool
	}
	order := []key{}
	index := map[key]*merged{}

	for _, e := range entries {
		k := key{e.ecosystem, e.name, e.version}
		if _, exists := index[k]; !exists {
			order = append(order, k)
			index[k] = &merged{sources: map[string]bool{}, reasons: map[string]bool{}}
		}
		m := index[k]
		for _, s := range e.sources {
			m.sources[s] = true
		}
		if e.reason != "" {
			m.reasons[e.reason] = true
		}
	}

	// Sort for deterministic output: ecosystem → name → version.
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.eco != b.eco {
			return a.eco < b.eco
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.ver < b.ver
	})

	records := make([]CompiledEntry, 0, len(order))
	for _, k := range order {
		m := index[k]

		sources := sortedKeys(m.sources)
		reasons := sortedKeys(m.reasons)

		reason := ""
		if len(reasons) > 0 {
			reason = strings.Join(reasons, ", ")
		}

		records = append(records, CompiledEntry{
			Ecosystem: k.eco,
			Name:      k.name,
			Version:   k.ver,
			Reason:    reason,
			Sources:   sources,
		})
	}

	outPath, err = compiledIndexPath()
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return "", 0, err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return "", 0, err
	}
	defer out.Close()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(records); err != nil {
		return "", 0, err
	}

	return outPath, len(records), nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// MatchBlocklists checks the given packages against all loaded blocklist files
// and returns synthetic Vulnerability entries for any matches.
func MatchBlocklists(packages []schema.Package) ([]schema.Vulnerability, error) {
	entries, err := loadBlocklists()
	if err != nil || len(entries) == 0 {
		return nil, err
	}

	type key struct{ eco, name, version string }
	exact := map[key][]blocklistEntry{}
	wild := map[key][]blocklistEntry{}

	for _, e := range entries {
		k := key{e.ecosystem, strings.ToLower(e.name), e.version}
		if e.version == "" {
			wild[key{e.ecosystem, strings.ToLower(e.name), ""}] = append(
				wild[key{e.ecosystem, strings.ToLower(e.name), ""}], e)
		} else {
			exact[k] = append(exact[k], e)
		}
	}

	type hit struct {
		sources []string
		reasons []string
	}
	type pkgKey struct{ eco, name, ver string }
	hitOrder := []pkgKey{}
	hits := map[pkgKey]*hit{}

	for _, pkg := range packages {
		eco := pkg.Ecosystem
		nameLower := strings.ToLower(pkg.Name)
		ver := pkg.Version

		var matched []blocklistEntry
		if m, ok := exact[key{eco, nameLower, ver}]; ok {
			matched = append(matched, m...)
		}
		if m, ok := wild[key{eco, nameLower, ""}]; ok {
			matched = append(matched, m...)
		}

		for _, m := range matched {
			k := pkgKey{eco, pkg.Name, ver}
			if _, exists := hits[k]; !exists {
				hitOrder = append(hitOrder, k)
				hits[k] = &hit{}
			}
			h := hits[k]
			for _, s := range m.sources {
				h.sources = append(h.sources, s)
			}
			if m.reason != "" {
				h.reasons = append(h.reasons, m.reason)
			}
		}
	}

	var vulns []schema.Vulnerability
	for _, k := range hitOrder {
		h := hits[k]

		uniqSources := dedupe(h.sources)
		uniqReasons := dedupe(h.reasons)

		reason := "supply-chain attack"
		if len(uniqReasons) > 0 {
			reason = strings.Join(uniqReasons, ", ")
		}
		title := strings.ToUpper(reason[:1]) + strings.ToLower(reason[1:]) + " detected"
		desc := "This package appears in " + strings.Join(uniqSources, ", ") +
			". Reason: " + reason + ". Remove or replace it immediately."

		vulns = append(vulns, schema.Vulnerability{
			ID:               "BLOCKLIST:" + k.name + "@" + k.ver,
			Package:          k.name,
			Ecosystem:        k.eco,
			InstalledVersion: k.ver,
			Severity:         schema.SeverityCritical,
			Title:            title,
			Description:      desc,
		})
	}
	return vulns, nil
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
