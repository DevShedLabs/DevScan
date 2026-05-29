package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/DevShedLabs/devscan/internal/detectors"
	"github.com/DevShedLabs/devscan/internal/inspectors"
	"github.com/DevShedLabs/devscan/internal/schema"
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

func deduplicatePackages(packages []schema.Package) []schema.Package {
	seen := map[string]bool{}
	out := make([]schema.Package, 0, len(packages))
	for _, p := range packages {
		key := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func runFullScan(opts scanOptions) (*schema.Report, error) {
	start := time.Now()

	report := &schema.Report{
		Meta: schema.Meta{
			Version:   "0.1.0",
			Timestamp: start,
			Target:    opts.scope,
			Path:      opts.path,
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
	report.Packages = deduplicatePackages(allPackages)

	// Query advisories
	client := advisory.NewClient(opts.noCache)
	vulns, err := client.QueryPackages(report.Packages)
	if err == nil {
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
