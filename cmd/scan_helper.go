package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/DevShedLabs/devscan/internal/detectors"
	"github.com/DevShedLabs/devscan/internal/inspectors"
	"github.com/DevShedLabs/devscan/internal/schema"
	"github.com/DevShedLabs/devscan/internal/sysinfo"
	"github.com/DevShedLabs/devscan/internal/traverse"
	"github.com/DevShedLabs/devscan/internal/versions"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	scope   string // "global" | "project"
	path    string
	depth   int
	noCache bool
}

func scanOptsFromCmd(cmd *cobra.Command) scanOptions {
	project, _ := cmd.Flags().GetBool("project")
	global, _ := cmd.Flags().GetBool("global")
	path, _ := cmd.Flags().GetString("path")
	noCache, _ := cmd.Flags().GetBool("no-cache")
	depth, _ := cmd.Flags().GetInt("depth")

	scope := "global"
	if project || path != "" {
		scope = "project"
	}
	_ = global

	if path == "" && scope == "project" {
		cwd, _ := os.Getwd()
		path = cwd
	}

	return scanOptions{scope: scope, path: path, depth: depth, noCache: noCache}
}

// deduplicatePackages collapses packages with the same ecosystem+name+version
// into one entry, merging all distinct paths. The returned packages are unique
// by identity; the path index maps each identity key to all known paths.
func deduplicatePackages(packages []schema.Package) ([]schema.Package, map[string][]string) {
	type entry struct {
		pkg   schema.Package
		paths map[string]bool
	}
	order := []string{}
	entries := map[string]*entry{}

	for _, p := range packages {
		key := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if _, exists := entries[key]; !exists {
			order = append(order, key)
			entries[key] = &entry{pkg: p, paths: map[string]bool{}}
		}
		if p.Path != "" {
			entries[key].paths[p.Path] = true
		}
	}

	out := make([]schema.Package, 0, len(order))
	pathIndex := make(map[string][]string, len(order))
	for _, key := range order {
		e := entries[key]
		out = append(out, e.pkg)
		paths := make([]string, 0, len(e.paths))
		for path := range e.paths {
			paths = append(paths, path)
		}
		pathIndex[key] = paths
	}
	return out, pathIndex
}

func runFullScan(opts scanOptions) (*schema.Report, error) {
	start := time.Now()

	sys := sysinfo.Collect()
	report := &schema.Report{
		Meta: schema.Meta{
			Version:   "0.1.0",
			Timestamp: start,
			Target:    opts.scope,
			Path:      opts.path,
			OS:        sys.OS,
			OSVersion: sys.OSVersion,
			Arch:      sys.Arch,
			Chip:      sys.Chip,
		},
		System: map[string]string{},
	}

	// Detect runtimes and enrich with latest version info
	report.Runtimes = detectors.RunAll(detectors.All())
	versions.Enrich(report.Runtimes)

	// Collect project paths to scan
	paths := projectPaths(opts)

	// Inspect packages across all paths
	var allPackages []schema.Package
	for _, p := range paths {
		pkgs := inspectors.RunAll(inspectors.All(), opts.scope, p)
		allPackages = append(allPackages, pkgs...)
	}
	pkgs, pathIndex := deduplicatePackages(allPackages)
	report.Packages = pkgs

	// Query advisories
	client := advisory.NewClient(opts.noCache)
	vulns, err := client.QueryPackages(report.Packages)
	if err == nil {
		// Attach all known install paths to each vulnerability.
		for i, v := range vulns {
			key := v.Ecosystem + "|" + v.Package + "|" + v.InstalledVersion
			vulns[i].Paths = pathIndex[key]
		}
		report.Vulnerabilities = vulns
	}

	report.Meta.DurationMs = time.Since(start).Milliseconds()
	report.ComputeSummary()

	return report, nil
}

// projectPaths returns the list of directories to inspect based on scope and depth.
func projectPaths(opts scanOptions) []string {
	if opts.scope == "global" {
		return []string{""}
	}
	if opts.depth <= 0 {
		return []string{opts.path}
	}
	projects := traverse.FindProjects(opts.path, opts.depth)
	if len(projects) == 0 {
		return []string{opts.path}
	}
	fmt.Fprintf(os.Stderr, "Found %d project(s) under %s\n", len(projects), opts.path)
	return projects
}
