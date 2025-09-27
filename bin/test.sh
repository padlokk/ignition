#!/bin/bash
# Ignite Test Runner
# Provides a thin wrapper around the planned test suites described in
# docs/ref/rsb/TEST_ORGANIZATION.md.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

BOXY=""
if command -v boxy >/dev/null 2>&1; then
    BOXY="boxy"
fi

# Suite → command mapping (shell snippets executed via bash -c)
declare -A SUITES=(
    [unit]="cargo test --lib"
    [proofs]="cargo test proofs"
    [manifests]="cargo test manifests"
    [storage]="cargo test storage"
    [cli]="cargo test cli"
    [integration]="cargo test integration"
    [security]="cargo test security"
    [smoke]="cargo test smoke"
    [all]="bash -c '$0 run unit && $0 run proofs && $0 run manifests && $0 run storage && $0 run cli && $0 run integration && $0 run security'"
    [full]="bash -c '$0 run all'"
)

print_help() {
    cat <<'HELP'
Ignite Test Runner
Usage:
  test.sh help                     Show this help
  test.sh list                     List available suites
  test.sh run <suite> [--nocapture]  Execute a suite (default smoke)

Suites:
  unit        Core authority unit tests (Rust)
  proofs      Ed25519 proof engine suite
  manifests   Affected-key manifest validation
  storage     Vault/XDG storage adapters
  cli         RSB CLI smoke harness
  integration End-to-end authority workflows
  security    Safety/danger-mode validations
  smoke       Quick confidence suite
  all         Run all ignite suites
  full        Alias for comprehensive regression

Structure guidance: docs/ref/rsb/TEST_ORGANIZATION.md
HELP
}

list_suites() {
    if [[ -n "$BOXY" ]]; then
        {
            echo "Suites:"
            for name in $(printf "%s\n" "${!SUITES[@]}" | sort); do
                target="${SUITES[$name]}"
                printf "  • %-11s %s\n" "$name" "$target"
            done
            echo
            echo "See docs/ref/rsb/TEST_ORGANIZATION.md for layout requirements."
        } | $BOXY --theme info --title "🔥 Ignite Suites" --width max
    else
        echo "Suites:"
        for name in $(printf "%s\n" "${!SUITES[@]}" | sort); do
            target="${SUITES[$name]}"
            printf "  %-11s %s\n" "$name" "$target"
        done
        echo
        echo "See docs/ref/rsb/TEST_ORGANIZATION.md for layout requirements."
    fi
}

run_suite() {
    local suite="$1"
    shift || true

    if [[ -z "$suite" ]]; then
        suite="smoke"
    fi

    if [[ -z "${SUITES[$suite]:-}" ]]; then
        echo "❌ unknown suite: $suite" >&2
        echo "Available: ${!SUITES[*]}" >&2
        exit 1
    fi

    local command="${SUITES[$suite]}"
    if [[ "$command" == bash* ]]; then
        eval "$command"
        return
    fi

    if [[ -n "$BOXY" ]]; then
        echo "🚀 ignite suite → $suite" | $BOXY --theme success --title "🧪 Ignite Tests" --width max
    else
        echo "🚀 ignite suite → $suite"
    fi

    # allow passthrough flags (e.g., -- --nocapture)
    bash -c "$command" "$@"
}

case "${1:-run}" in
    help|-h|--help)
        print_help
        ;;
    list)
        list_suites
        ;;
    run)
        shift || true
        run_suite "$@"
        ;;
    *)
        # default to running smoke
        run_suite smoke "$@"
        ;;
esac
