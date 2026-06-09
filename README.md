# DevScan

![Version](https://img.shields.io/github/v/tag/DevShedLabs/devscan?label=version&sort=semver)
![License](https://img.shields.io/github/license/DevShedLabs/devscan)
![Go](https://img.shields.io/badge/built%20with-Go-00ADD8)

A developer environment security and health scanner. Detects runtimes, inspects installed packages, and surfaces known vulnerabilities and outdated dependencies — across your global environment or a specific project.

Built with Go. Designed to be scriptable, CI-friendly, and extensible.

---

## Install

```bash
# Latest release
go install github.com/DevShedLabs/devscan@latest

# Specific version
go install github.com/DevShedLabs/devscan@v0.1.4
```

Make sure `~/go/bin` is on your `$PATH`. Add this to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.)  
if it isn't already:

```bash
export PATH="$HOME/go/bin:$PATH"
```

Then reload your shell (`source ~/.zshrc`) or open a new terminal.

Once installed, keep devscan up to date with:

```bash
devscan update
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
| `devscan locate` | Filesystem paths for every vulnerable package |
| `devscan scan` | Raw JSON scan output for piping |
| `devscan fix` | Suggested fix commands |
| `devscan report` | Export a full report as Markdown, HTML, or JSON |
| `devscan keyscan` | Scan files for exposed secrets, API keys, and tokens |
| `devscan compile` | Compile blocklist resources into a single index |
| `devscan intercept` | Manage package manager shims for real-time install protection |

---

## Usage

All commands scan the current directory by default. Use `--global` to scan the entire machine instead.

```bash
# Get the version you have installed
devscan --version

# Full health report for the current project
devscan doctor

# Audit the current project for vulnerabilities
devscan audit

# Scan the whole machine (global packages)
devscan audit --global

# Filter to high severity and above
devscan audit --severity high

# Show exactly where vulnerable packages are installed
devscan locate

# Scan a specific path
devscan doctor --path ./my-app

# Scan a project and all sub-projects up to 2 levels deep
devscan doctor --path ./my-app --depth 2

# Machine-readable output
devscan doctor --format json

# CI: exit non-zero if critical vulns found
devscan audit --severity critical
```

---

## Reports

Generate a shareable report in Markdown, HTML, or JSON:

```bash
# Format is inferred from the output file extension
devscan report --output report.html
devscan report --output report.md
devscan report --output scan.json

# Or specify the format explicitly (stdout)
devscan report --html
devscan report --md
devscan report --json

# Scoped to a path
devscan report --output report.html --path ./my-app

# Traverse sub-projects
devscan report --output report.html --path ./my-app --depth 2

# Clean public report (strips internal paths and package inventory)
devscan report --output security-report.md --public
```

Reports include:
- System info: OS, version, chip, architecture
- Summary cards with severity counts and scan duration
- Runtime versions with outdated status
- Vulnerabilities grouped by severity, with OSV advisory links, fixed-in versions, and fix commands
- Filesystem paths for every vulnerable package installation
- Full package inventory

---

## Blocklists

Augment OSV vulnerability data with your own curated supply-chain blocklists. Any package matched against a blocklist is reported as **critical** severity alongside normal OSV findings.

### Setup

Drop blocklist files into `~/.devscan/resources/`:

```bash
mkdir -p ~/.devscan/resources
cp miasma-attack-packages.csv ~/.devscan/resources/
cp malwareDatabase_js.json ~/.devscan/resources/
```

Then compile them into a single fast-load index:

```bash
devscan compile
```

This writes `~/.devscan/devscan.json`. All subsequent scans load the compiled index automatically — no flags needed, no rebuild required.

After adding or updating source files, re-run `devscan compile` to regenerate the index.

### Supported formats

**CSV** — header row required, `Ecosystem` and `Name` columns required, `Version` optional (omit to match any version):

```
Ecosystem,Namespace,Name,Version,Artifact,Published,Detected
npm,,chai-utils-test,4.5.3,,,2026-06-04T00:00:00Z
pypi,,tlask,3.1.4,,,2026-06-07T15:00:00Z
```

**JSON (generic)** — ecosystem must be specified:

```json
[
  { "ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0", "reason": "MALWARE" }
]
```

**JSON (Aikido-style)** — auto-detected by the `package_name` field, treated as npm:

```json
[
  { "package_name": "evil-pkg", "version": "1.0.0", "reason": "MALWARE" }
]
```

### Deduplication

Packages flagged by multiple sources are merged into a single finding. The vulnerability description lists every source file that matched, e.g.:

```
[CRIT] chai-utils-test@4.5.3
  Malware detected
  This package appears in malwareDatabase_js.json, miasma-attack-packages.csv.
  Reason: MALWARE. Remove or replace it immediately.
```

### Directory layout

```
~/.devscan/
  resources/           ← drop source files here (*.csv, *.json)
  devscan.json         ← compiled index (auto-used by all scans)
```

---

## Key Scanning

Scan source files for exposed secrets, API keys, and tokens:

```bash
# Scan current directory
devscan keyscan

# Scan a specific path
devscan keyscan --path ./my-app

# Limit depth (useful for large monorepos)
devscan keyscan --path /Users/me/projects --depth 3

# Filter to critical only
devscan keyscan --severity critical

# Export as HTML or Markdown
devscan keyscan --path ./ --format html --output keyscan.html
devscan keyscan --path ./ --format md --output keyscan.md

# Redirect output (also enables live progress counter)
devscan keyscan --path /Users/me/projects --depth 3 > keyscan.html
```

Detected secret types:

| Category | Examples |
|---|---|
| AI providers | OpenAI, Anthropic, Google AI, Groq, OpenRouter, Cohere, Replicate |
| Cloud | AWS access/secret keys, GCP service accounts, Firebase, Azure |
| Source control | GitHub tokens (ghp_, ghs_, gho_, github_pat_) |
| Payments | Stripe live keys (sk_live_, pk_live_), PayPal, Braintree |
| Messaging | Slack tokens & webhooks, Twilio, SendGrid, Mailgun |
| Registries | npm tokens |
| Infrastructure | Heroku, Vercel, Netlify, Render, Cloudflare, DigitalOcean |
| Monitoring | Datadog, Sentry, New Relic |
| Private keys | RSA, EC, DSA, OpenSSH private key headers |
| Database URLs | Postgres, MySQL, MongoDB, Redis URLs with embedded credentials |
| Named vars | Any `<SERVICE>_KEY`, `<SERVICE>_TOKEN`, `<SERVICE>_SECRET` where the service name is a known provider |

Skips automatically: `node_modules/`, `vendor/`, `.git/`, `dist/`, binary files, documentation (`.md`, `.rst`, `.txt`), and example/template files (`.example`, `.sample`, `.dist`).

All matched values are **redacted** in output — only enough context is shown to identify the type of secret, never the full value.

### Include in full reports

Add a secrets section to any `devscan report`:

```bash
devscan report --html --include-keys --output report.html
devscan report --md --include-keys
devscan report --json --include-keys --output report.json
```

---

## Flags

```
--format string      Output format: table|json|compact (default "table")
--severity string    Filter by severity: critical|high|medium|low
--ecosystem string   Filter by ecosystem: npm|pypi|packagist|crates.io|go
--global             Scan global packages (machine-wide)
--project            Scan current project directory (default)
--path string        Explicit project path to scan
--depth int          Traverse subdirectories up to this depth (0 = path only)
--no-color           Disable color output
--no-cache           Bypass cache and force a fresh advisory lookup
--public             Removes data not needed for public view, eg. repo
-o, --output string  Write report to file (report command only)
```

---

## Fix Commands

When a fix is available, devscan generates the exact command to run:

| Ecosystem | Example |
|---|---|
| npm | `npm install pkg@^1.2.3` |
| pypi | `pip install --upgrade pkg>=1.2.3` |
| packagist | `composer require vendor/pkg:^1.2.3` |
| crates.io | `cargo update -p pkg --precise 1.2.3` |
| go | `go get module@v1.2.3` |
| gem | `gem update pkg` |

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

## Intercept

Intercept wraps npm, pip, cargo, and bun with shims that check every explicit package install against your compiled blocklist **before the package is fetched** — before any `postInstall` hook can execute.

Most supply-chain attacks run malicious code during installation via post-install hooks, and use tools like Bun and Rust to do further damage on the machine. Intercept stops them at the gate.

### How it works

When enabled, devscan writes symlinks into `~/.devscan/shims/`:

```
~/.devscan/shims/npm      →  devscan binary
~/.devscan/shims/bun      →  devscan binary
~/.devscan/shims/pip      →  devscan binary
~/.devscan/shims/pip3     →  devscan binary
~/.devscan/shims/cargo    →  devscan binary
~/.devscan/shims/go       →  devscan binary
~/.devscan/shims/composer →  devscan binary
```

The shims directory sits at the front of your `PATH`. When you run `npm install evil-pkg`, the shim runs first, checks the package against your compiled blocklist, and either blocks with a warning or transparently execs the real binary. Non-install commands (`npm run`, `cargo build`, etc.) are passed through instantly with zero overhead.

### Setup

```bash
# 1. Compile your blocklists (required — shims check the compiled index)
devscan compile

# 2. Enable shims and patch your shell profile
devscan intercept enable

# 3. Reload your shell
source ~/.zshrc
```

> Re-run `devscan intercept enable` any time to sync shims — it is safe to run repeatedly and will add any missing shims without affecting existing ones.

### Commands

```bash
# Enable shims and patch shell profile
devscan intercept enable

# Disable and clean up
devscan intercept disable

# Check which shims are active and whether the shims dir is on PATH
devscan intercept status
```

### What a blocked install looks like

```
╔══════════════════════════════════════════════════════════════════════╗
║                        DEVSCAN BLOCKED                               ║
╚══════════════════════════════════════════════════════════════════════╝

  [MALWARE]    chai-utils-test@4.5.3
               Found in: malwareDatabase_js.json

  npm install was blocked. Remove this package from your command and try again.
  Run `devscan audit` for a full vulnerability report.
```

The warning is printed to stderr in red so it stands out from the surrounding install output. The process exits 1, preventing the install from proceeding.

### Keeping shims current

`devscan update` automatically rewrites shims to point at the new binary. If a new package manager is added in a future release, re-run `devscan intercept enable` to write the new shims — it is idempotent and safe to run at any time.

Both explicit installs and lockfile installs are scanned. Lockfile commands (`npm ci`, `bun install`, `composer install`, `composer update`, `go get`) read the lock file from the current directory and check every pinned package before the real command runs.

### Supported package managers

| Manager | Command intercept |
|---|---|
| npm | `npm install`, `npm i`, `npm add`, `npm ci` (lockfile) |
| bun | `bun add`, `bun install` (lockfile) |
| pip | `pip install`, `pip3 install` |
| cargo | `cargo add`, `cargo install` |
| go | `go get`, `go install`, `go.sum` (lockfile) |
| composer | `composer require`, `composer install`, `composer update` (lockfile) |

---

## Cache

Network results are cached locally to keep scans fast.

| Data | TTL | Location (macOS) |
|---|---|---|
| Vulnerability advisories (OSV.dev) | 1 hour | `~/Library/Caches/devscan/` |
| Runtime latest versions | 7 days | `~/Library/Caches/devscan/versions/` |

On Linux: `~/.cache/devscan/` · On Windows: `%LocalAppData%\devscan\`

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

| Ecosystem | Runtime | Packages | Vulnerabilities |
|---|---|---|---|
| Node.js / npm | ✓ | ✓ | ✓ via OSV.dev |
| Bun | ✓ | ✓ (via npm) | ✓ via OSV.dev |
| Python / pip | ✓ | ✓ | ✓ via OSV.dev |
| PHP / Composer | ✓ | ✓ | ✓ via OSV.dev |
| Rust / Cargo | ✓ | ✓ | ✓ via OSV.dev |
| Go modules | ✓ | ✓ (project) | ✓ via OSV.dev |
| Git | ✓ | — | — |

Vulnerability data is sourced from [OSV.dev](https://osv.dev) — an open, community-driven vulnerability database covering npm, PyPI, Go, crates.io, Packagist, RubyGems, and more.

Large scans (1000+ packages) are automatically chunked into batches to stay within OSV API limits.

---

## Architecture

```
devscan/
  cmd/                  # CLI commands (Cobra)
  internal/
    detectors/          # Runtime detection (node, bun, python, git, php, rust, go)
    inspectors/         # Package inspection (npm, pip, composer, cargo, gomod)
    advisory/           # Vulnerability lookups (OSV.dev + local blocklists) with 1hr cache
    intercept/          # Package manager shims — pre-install supply-chain blocking
    intercept/managers/ # Per-manager argument parsing (npm, pip, cargo, bun)
    versions/           # Runtime latest-version checks with 7-day cache
    keyscanner/         # Secret and API key detection (file-based pattern scanning)
    sysinfo/            # OS, chip, and architecture detection
    traverse/           # Sub-project discovery by manifest files
    output/             # Terminal renderers (table, JSON, compact)
    report/             # Export renderers (Markdown, HTML, JSON)
    schema/             # Shared types
```

The JSON output schema is the central contract. The CLI, and future TUI and GUI layers, are all thin wrappers on top of it.

---

## Roadmap

- [x] Runtime latest-version checks — Go, Node, Bun, Python, PHP, Rust, Git
- [x] Fix commands for all supported ecosystems
- [x] Sub-project traversal with `--depth`
- [x] Filesystem paths for vulnerable packages
- [x] System info in reports (OS, chip, arch)
- [x] HTML and Markdown report export
- [x] Ruby / gem support
- [x] Homebrew package inspection
- [x] Secret and API key scanning (`devscan keyscan`)
- [x] `--include-keys` flag to add secrets section to full reports
- [x] Local blocklist support — CSV and JSON supply-chain attack databases (`~/.devscan/resources/`)
- [x] `devscan compile` to merge blocklists into a fast single index
- [x] Pre-install intercept shims for npm, pip, cargo, bun, go, composer (`devscan intercept`)
- [x] Intercept: lockfile scanning for `npm ci`, `bun install`, `composer install/update`, `go get`
- [ ] System package managers — dpkg (Debian/Ubuntu), rpm (Fedora/RHEL), apk (Alpine)
- [ ] Baseline diff (`--compare baseline.json`)
- [ ] CI summary output (GitHub Actions annotations)
- [ ] `--ignore` flag to suppress known/accepted advisories

---

## License

MIT
