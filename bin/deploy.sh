#!/bin/bash
set -euo pipefail

# Ignite Deploy Script - installs ignite CLI into ~/.local/bin

LIB_DIR="$HOME/.local/lib/odx/ignite"
BIN_DIR="$HOME/.local/bin"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BINARY_NAME="ignite"

VERSION=$(grep '^version' "$ROOT_DIR/Cargo.toml" | head -1 | cut -d'"' -f2)

has_boxy() { command -v boxy >/dev/null 2>&1; }

ceremony_msg() {
    local msg="$1"
    local theme="${2:-info}"
    if has_boxy; then
        echo "$msg" | boxy --theme "$theme" --width max
    else
        echo "$msg"
    fi
}

step_msg() {
    local step="$1"
    local desc="$2"
    if has_boxy; then
        printf "%s\n%s\n" "$step" "• $desc" | boxy --style rounded --width max --title "📦 Deploy Step"
    else
        echo "$step: $desc"
    fi
}

ceremony_msg "🔥 IGNITE DEPLOYMENT CEREMONY v$VERSION" "success"

deploy_dir() {
    mkdir -p "$1"
}

step_msg "Step 1" "Building ignite v$VERSION"
cd "$ROOT_DIR"
cargo build --release --bin ignite

if [[ ! -f "$ROOT_DIR/target/release/${BINARY_NAME}" ]]; then
    ceremony_msg "❌ Binary not found at target/release/${BINARY_NAME}" "error"
    exit 1
fi

step_msg "Step 2" "Preparing library directory: $LIB_DIR"
deploy_dir "$LIB_DIR"

step_msg "Step 3" "Copying ignite binary"
cp "$ROOT_DIR/target/release/${BINARY_NAME}" "$LIB_DIR/${BINARY_NAME}"
chmod +x "$LIB_DIR/${BINARY_NAME}"

step_msg "Step 4" "Preparing bin directory: $BIN_DIR"
deploy_dir "$BIN_DIR"

step_msg "Step 5" "Creating symlink"
if [[ -L "$BIN_DIR/${BINARY_NAME}" || -f "$BIN_DIR/${BINARY_NAME}" ]]; then
    rm "$BIN_DIR/${BINARY_NAME}"
fi
ln -s "$LIB_DIR/${BINARY_NAME}" "$BIN_DIR/${BINARY_NAME}"
echo "  Created: $BIN_DIR/${BINARY_NAME} → $LIB_DIR/${BINARY_NAME}"

step_msg "Step 6" "Verifying deployment"
if [[ ! -x "$LIB_DIR/${BINARY_NAME}" ]]; then
    ceremony_msg "❌ ignite is not executable at $LIB_DIR/${BINARY_NAME}" "error"
    exit 1
fi
if [[ ! -L "$BIN_DIR/${BINARY_NAME}" ]]; then
    ceremony_msg "❌ Symlink not created at $BIN_DIR/${BINARY_NAME}" "error"
    exit 1
fi

step_msg "Step 7" "Smoke testing ignite --help"
if ! "$BIN_DIR/ignite" --help >/dev/null 2>&1; then
    ceremony_msg "❌ ignite command failed initial test" "error"
    exit 1
fi
echo "✅ ignite command operational"

ceremony_msg "✅ IGNITE v$VERSION DEPLOYED" "success"

echo "📍 Library : $LIB_DIR/${BINARY_NAME}"
echo "📍 Symlink : $BIN_DIR/${BINARY_NAME}"
echo
if has_boxy; then
    {
        echo "🔥 Ignite - Authority chain CLI"
        echo
        echo "💡 Quick actions:"
        echo "   ignite status                     # Authority health"
        echo "   ignite proof --verify --all       # Proof integrity"
        echo "   ignite manifest --verify <file>   # Manifest audit"
        echo
        echo "📚 Docs: docs/ref/IGNITE_CLI.md"
    } | boxy --theme success --header "🚀 Ignite Ready" --width max
else
    echo "Try:"
    echo "  ignite status"
    echo "  ignite proof --verify --all"
fi

echo
step_msg "🧪 Quick Test" "Verifying proof/manifest subcommands"
if "$BIN_DIR/ignite" proof --help >/dev/null 2>&1; then
    echo "✅ proof subcommand available"
else
    ceremony_msg "⚠️ proof subcommand help failed (wired later)" "warning"
fi

echo "✅ Deployment complete"
