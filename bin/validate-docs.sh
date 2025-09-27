#!/bin/bash
#===============================================================================
# 🔍 IGNITE DOCUMENTATION VALIDATOR
#===============================================================================
# Silent on success, noisy on failure. Ensures core reference + process docs
# are present and up to date for the ignite authority project.
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ERRORS=0
WARNINGS=0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

err()   { echo -e "${RED}ERROR${NC}: $1" >&2; ((ERRORS++)); }
warn()  { echo -e "${YELLOW}WARN${NC}: $1" >&2; ((WARNINGS++)); }
info()  { [[ "${VERBOSE:-false}" == "true" ]] && echo -e "${GREEN}OK${NC}: $1"; }

require_file() {
    local path="$1"; local label="$2"
    if [[ -f "$path" ]]; then
        info "$label"
    else
        err "$label missing ($path)"
    fi
}

require_dir() {
    local path="$1"; local label="$2"
    if [[ -d "$path" ]]; then
        info "$label"
    else
        err "$label missing ($path)"
    fi
}

check_staleness() {
    local file="$1"; local max_days="$2"; local label="$3"
    [[ -f "$file" ]] || return

    local mtime
    if [[ "$(uname)" == "Darwin" ]]; then
        mtime=$(stat -f %m "$file")
    else
        mtime=$(stat -c %Y "$file")
    fi
    local age=$(( ( $(date +%s) - mtime ) / 86400 ))
    if (( age > max_days )); then
        warn "$label is $age days old (max $max_days)"
    else
        info "$label fresh ($age d)"
    fi
}

check_refs() {
    local file="$1"; local label="$2"
    [[ -f "$file" ]] || return
    local missing=0
    while IFS= read -r ref; do
        [[ -z "$ref" ]] && continue
        if [[ ! -e "$ref" ]]; then
            err "$label references missing path: $ref"
            missing=1
        fi
    done < <(grep -oE '(docs|bin)/[A-Za-z0-9_/.-]+' "$file" | sort -u || true)
    (( missing == 0 )) && info "$label references ok"
}

echo "🔍 Validating Ignite documentation…"

# Core entry points
require_file "START.txt" "START.txt present"
require_file "README.md" "README present"
require_file "LICENSE" "LICENSE present"

# Process docs
require_dir "docs/procs" "Process docs directory"
require_file "docs/procs/PROCESS.txt" "PROCESS.txt present"
require_file "docs/procs/CONTINUE.md" "CONTINUE.md present"
require_file "docs/procs/TASKS.txt" "TASKS.txt present"
require_file "docs/procs/ROADMAP.md" "ROADMAP.md present"
require_file "docs/procs/QUICK_REF.txt" "QUICK_REF present"

# Reference docs
require_dir "docs/ref" "Reference docs directory"
require_file "docs/ref/IGNITE_CONCEPTS.md" "Ignite concept doc"
require_file "docs/ref/IGNITE_MANIFEST.md" "Manifest specification"
require_file "docs/ref/IGNITE_PROOFS.md" "Proof engine spec"
require_file "docs/ref/IGNITE_CLI.md" "CLI reference"
require_dir "docs/ref/rsb" "RSB reference bundle"
require_file "docs/ref/rsb/MODULE_SPEC.md" "RSB module spec"
require_file "docs/ref/rsb/TEST_ORGANIZATION.md" "RSB test organization"

# Optional historical cage docs (informational)
if [[ -d "docs/cage" ]]; then
    info "cage reference docs detected"
fi

# Staleness checks
check_staleness "docs/procs/CONTINUE.md" 7 "CONTINUE.md"
check_staleness "docs/procs/TASKS.txt" 14 "TASKS.txt"
check_staleness "docs/ref/IGNITE_CONCEPTS.md" 30 "IGNITE_CONCEPTS"

# Cross-reference checks
check_refs "docs/ref/IGNITE_CONCEPTS.md" "IGNITE_CONCEPTS"
check_refs "docs/ref/IGNITE_MANIFEST.md" "IGNITE_MANIFEST"
check_refs "docs/ref/IGNITE_PROOFS.md" "IGNITE_PROOFS"
check_refs "docs/ref/IGNITE_CLI.md" "IGNITE_CLI"

if (( ERRORS == 0 )); then
    [[ -n "$BOXY" ]] && echo "✅ docs ok" | $BOXY --theme success || echo "✅ Ignite docs validated"
else
    echo "❌ documentation validation failed ($ERRORS errors, $WARNINGS warnings)" >&2
    exit 1
fi
