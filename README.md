# devscan

A developer environment security and health scanner. Detects runtimes, inspects installed packages, and surfaces known vulnerabilities and outdated dependencies — across your global environment or a specific project.

Built with Go. Designed to be scriptable, CI-friendly, and extensible.

---

## Install

```bash
go install github.com/DevShedLabs/devscan@latest
```

Or build from source:

```bash
git clone https://github.com/DevShedLabs/devscan
cd devscan
go build -o devscan .
```

---

## Commands

| Command | Description |
|---|---|
| `devscan doctor` | Full scan: runtimes, packages, vulnerabilities, outdated deps |
| `devscan audit` | Vulnerabilities only |
| `devscan outdated` | Version drift only |
| `devscan list` | Inventory of detected runtimes and packages |
| `devscan scan` | Raw JSON scan output for piping |
| `devscan fix` | Suggested fix commands |

---

## Usage

```bash
# Full health report
devscan doctor

# Audit for vulnerabilities, filter to high and above
devscan audit --severity high

# Scan a specific project
devscan doctor --path ./my-app

# Machine-readable output
devscan doctor --format json

# CI: exit non-zero if critical vulns found
devscan audit --severity critical
```

---

## Flags

```
--format string      Output format: table|json|compact (default "table")
--severity string    Filter by severity: critical|high|medium|low
--ecosystem string   Filter by ecosystem: npm|pypi|gem|go
--global             Scan global packages (default)
--project            Scan current project directory
--path string        Explicit project path to scan
--no-color           Disable color output
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | General error |
| `2` | Vulnerabilities found |
| `3` | Critical vulnerabilities found |
| `4` | Outdated packages found |

Useful for CI pipelines:

```yaml
- name: Security scan
  run: devscan audit --severity high
```

---

## Cache

Advisory results from OSV.dev are cached for 1 hour to avoid redundant network requests on repeated scans.

| OS | Cache location |
|---|---|
| macOS | `~/Library/Caches/devscan/` |
| Linux | `~/.cache/devscan/` |
| Windows | `%LocalAppData%\devscan\` |

Force a fresh lookup at any time:

```bash
devscan doctor --no-cache
```

---

## Config File

Place `.devscan.json` in your project root or home directory:

```json
{
  "ignore": ["left-pad"],
  "severity_threshold": "medium",
  "ecosystems": ["npm", "pypi"],
  "auto_fix": false
}
```

---

## Supported Ecosystems

| Ecosystem | Packages | Vulnerabilities |
|---|---|---|
| Node.js / npm | ✓ | ✓ via OSV.dev |
| Python / pip | ✓ | ✓ via OSV.dev |
| More coming | — | — |

Vulnerability data is sourced from [OSV.dev](https://osv.dev) — an open, community-driven vulnerability database covering npm, PyPI, Go, Maven, and more.

---

## Architecture

```
devscan/
  cmd/                  # CLI commands (Cobra)
  internal/
    detectors/          # Runtime detection (node, python, git, ...)
    inspectors/         # Package inspection (npm, pip, ...)
    advisory/           # Vulnerability lookups (OSV.dev)
    output/             # Renderers (table, JSON, compact)
    schema/             # Shared types
```

The JSON output schema is the central contract. The CLI, and future TUI and GUI layers, are all thin wrappers on top of it.

---

## Roadmap

- [ ] Homebrew, Go modules, Ruby gems support
- [ ] CVSS score parsing for accurate severity levels
- [ ] Runtime latest-version checks (Node release API, python.org)
- [ ] TUI (Bubbletea)
- [ ] `--watch` mode
- [ ] Baseline diff (`--compare baseline.json`)
- [ ] Menu bar app (macOS)

---

## License

MIT
