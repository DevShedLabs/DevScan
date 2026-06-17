#!/usr/bin/env bash
# smoke.sh — exercise devscan against the current directory as the project
# Requires: devscan on $PATH (run `devscan install-skill` to set this up)
# Usage: bash smoke.sh [/path/to/project]
set -euo pipefail

PROJECT="${1:-$PWD}"
BIN="devscan"
PASS=0
FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $1: $2"; FAIL=$((FAIL+1)); }

# Confirm binary is available
echo "==> devscan binary"
command -v "$BIN" >/dev/null 2>&1 || { echo "FATAL: devscan not found on PATH"; exit 1; }
ok "binary on PATH"

# Version
echo "==> version"
OUT=$("$BIN" --version 2>&1)
[[ "$OUT" == *"devscan version"* ]] && ok "version" || fail "version" "$OUT"

# list --path (table)
echo "==> list --path"
OUT=$("$BIN" list --path "$PROJECT" 2>&1)
[[ "$OUT" == *"Packages scanned"* || "$OUT" == *"Summary"* ]] && ok "list --path" || fail "list --path" "$OUT"

# list --path --format json
echo "==> list --path --format json"
OUT=$("$BIN" list --path "$PROJECT" --format json 2>&1)
[[ "$OUT" == *'"packages"'* || "$OUT" == *'"runtimes"'* ]] && ok "list json" || fail "list json" "$OUT"

# scan --path --format json
echo "==> scan --path --format json"
OUT=$("$BIN" scan --path "$PROJECT" --format json 2>&1)
[[ "$OUT" == *'"meta"'* ]] && ok "scan json" || fail "scan json" "$OUT"

# audit --path
echo "==> audit --path"
OUT=$("$BIN" audit --path "$PROJECT" 2>&1)
[[ "$OUT" == *"Packages scanned"* || "$OUT" == *"Summary"* ]] && ok "audit --path" || fail "audit --path" "$OUT"

# outdated --path
echo "==> outdated --path"
OUT=$("$BIN" outdated --path "$PROJECT" 2>&1)
[[ "$OUT" == *"Packages scanned"* || "$OUT" == *"Summary"* ]] && ok "outdated --path" || fail "outdated --path" "$OUT"

# doctor --path
echo "==> doctor --path"
OUT=$("$BIN" doctor --path "$PROJECT" 2>&1)
[[ "$OUT" == *"Packages scanned"* || "$OUT" == *"Summary"* ]] && ok "doctor --path" || fail "doctor --path" "$OUT"

# report --path (default markdown)
echo "==> report --path"
OUT=$("$BIN" report --path "$PROJECT" 2>&1)
[[ "$OUT" == *"DevScan Report"* ]] && ok "report --path" || fail "report --path" "$OUT"

# locate --path
echo "==> locate --path"
OUT=$("$BIN" locate --path "$PROJECT" 2>&1)
[[ -n "$OUT" ]] && ok "locate --path" || fail "locate --path" "no output"

# fix --path
echo "==> fix --path"
OUT=$("$BIN" fix --path "$PROJECT" 2>&1)
[[ -n "$OUT" ]] && ok "fix --path" || fail "fix --path" "no output"

# keyscan exits with code 2 when findings are present; || true prevents set -e from aborting
echo "==> keyscan --path"
OUT=$("$BIN" keyscan --path "$PROJECT" --no-color 2>&1) || true
[[ "$OUT" == *"file:"* || "$OUT" == *"No findings"* || "$OUT" == *"secret"* ]] \
  && ok "keyscan" || fail "keyscan" "$OUT"

# keyscan --format json
echo "==> keyscan --path --format json"
OUT=$("$BIN" keyscan --path "$PROJECT" --format json 2>&1) || true
[[ "$OUT" == *'"findings"'* ]] && ok "keyscan json" || fail "keyscan json" "$OUT"

# osv --package (known vulnerable package)
echo "==> osv --package lodash"
OUT=$("$BIN" osv --package lodash 2>&1)
[[ "$OUT" == *"advisories"* || "$OUT" == *"GHSA"* ]] && ok "osv --package" || fail "osv --package" "$OUT"

# osv by advisory ID
echo "==> osv GHSA-29mw-wpgm-hmr9"
OUT=$("$BIN" osv GHSA-29mw-wpgm-hmr9 2>&1)
[[ "$OUT" == *"lodash"* || "$OUT" == *"ReDoS"* ]] && ok "osv ID lookup" || fail "osv ID lookup" "$OUT"

echo ""
echo "==> Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
