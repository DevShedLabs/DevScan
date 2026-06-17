---
name: run-devscan
description: Run devscan against any project to audit vulnerabilities, scan for secrets, check outdated packages, or generate a report. Use when asked to run devscan, audit a project, scan for secrets with keyscan, check outdated deps, or look up an OSV advisory.
---

devscan is a CLI security and health scanner for developer environments. It requires `devscan` on `$PATH` — install it with `go install github.com/DevShedLabs/devscan@latest`. The driver is `smoke.sh` in this skill directory; it exercises every subcommand against a given project path.

## Prerequisites

```bash
# Install devscan
go install github.com/DevShedLabs/devscan@latest

# Confirm
devscan --version
```

## Run (agent path)

Point devscan at the project directory. Most commands take `--path`:

```bash
# Full health check
devscan doctor --path /path/to/project

# Vulnerabilities only
devscan audit --path /path/to/project

# Outdated runtimes and packages
devscan outdated --path /path/to/project

# Scan for exposed secrets and API keys
devscan keyscan --path /path/to/project

# List all detected packages (JSON)
devscan list --path /path/to/project --format json

# Raw scan output (JSON, good for piping)
devscan scan --path /path/to/project --format json

# Generate a report
devscan report --path /path/to/project          # Markdown (default)
devscan report --path /path/to/project --html   # HTML
devscan report --path /path/to/project --format json

# Suggest fixes for vulnerable/outdated packages
devscan fix --path /path/to/project

# Show filesystem paths for vulnerable packages
devscan locate --path /path/to/project

# Look up an advisory by package name
devscan osv --package lodash

# Look up an advisory by ID (CVE, GHSA, OSV, etc.)
devscan osv GHSA-29mw-wpgm-hmr9
```

## Smoke test

Run all subcommands against a project and report PASS/FAIL:

```bash
bash ~/.claude/skills/run-devscan/smoke.sh /path/to/project
```

Omit the path to test against the current directory:

```bash
bash ~/.claude/skills/run-devscan/smoke.sh
```

Expected output ends with:
```
==> Results: 14 passed, 0 failed
```

## Global scan (no project path)

```bash
devscan doctor --global     # scan globally installed packages
devscan list --global
devscan audit --global
```

## Gotchas

- **`keyscan` exits with code 2** when it finds secrets — that is not an error. Scripts using `set -e` must append `|| true`: `OUT=$(devscan keyscan --path . 2>&1) || true`. Exit 0 = no findings, 2 = findings found.
- **`--no-color` does not suppress the progress bar** — `keyscan` writes `\r\033[K` to stderr regardless. Capture with `2>&1` and match on `file:` (present in every finding), not on the color-coded `[CRIT]` token.
- **Network-dependent commands** (`osv`, `audit`, `doctor`) call `api.osv.dev`. They time out or return empty in air-gapped environments — pass `--advisories-only` to skip the network lookup and use only local blocklists.
- **`scan` vs `list`**: `scan` emits raw JSON with no vulnerability data; `list` emits a human table (or JSON with `--format json`) and includes runtime detection. Use `scan` for piping, `list` for inspection.
- **`report --path`** defaults to Markdown on stdout. Use `--html` for an HTML file or `--format json` for machine-readable output.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `devscan: command not found` | Run `go install github.com/DevShedLabs/devscan@latest`; ensure `~/go/bin` is on `$PATH` |
| `osv` returns 0 results for a known package | Try `--no-cache` to bypass the local advisory cache |
| `audit` / `doctor` timeout | Network issue — use `--advisories-only` to skip OSV |
| `keyscan` finds secrets in test fixtures | Expected if the project has `testdata/` with intentional fixture keys |
