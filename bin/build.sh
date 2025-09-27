#!/bin/bash
# Ignite Build Script - Authority Chain & Ignition CLI
# Builds the standalone ignite CLI tool that drives the X->M->R->I->D workflows

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BUILD_TYPE="${1:-release}"
BUILD_MODE="${2:-optimized}"

banner() {
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}       Ignite Build System v0.1.0                   ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
    echo
}

check_age_installation() {
    if command -v age >/dev/null 2>&1; then
        AGE_VERSION=$(age --version 2>&1 | head -n1)
        echo -e "${GREEN}✅ age detected: ${AGE_VERSION}${NC}"
        return
    fi

    echo -e "${YELLOW}⚠️  age binary not found — Ignite delegates encryption to cage/age${NC}"
    echo -e "${YELLOW}🔧 attempting install (required for integration tests)…${NC}"

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y age
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y age
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm age
        else
            echo -e "${RED}❌ unsupported package manager; install age manually${NC}"
            echo "Download: https://github.com/FiloSottile/age/releases"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew >/dev/null 2>&1; then
            brew install age
        else
            echo -e "${RED}❌ Homebrew missing; install age manually${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ Unsupported platform. Install age manually.${NC}"
        exit 1
    fi

    if command -v age >/dev/null 2>&1; then
        AGE_VERSION=$(age --version 2>&1 | head -n1)
        echo -e "${GREEN}✅ age installed: ${AGE_VERSION}${NC}"
    else
        echo -e "${RED}❌ age installation failed${NC}"
        exit 1
    fi
}

build_release() {
    echo -e "${YELLOW}🚀 Building ignite release binary…${NC}"
    cargo build --release --bin ignite
    echo -e "${GREEN}✅ ignite release build complete${NC}"
}

build_debug() {
    echo -e "${YELLOW}🧪 Building ignite debug binary…${NC}"
    cargo build --bin ignite
    echo -e "${GREEN}✅ ignite debug build complete${NC}"
}

build_test() {
    echo -e "${YELLOW}🔍 Building + testing ignite…${NC}"
    cargo build --bin ignite
    cargo test
    echo -e "${GREEN}✅ ignite tests passed${NC}"
}

clean_build() {
    echo -e "${YELLOW}🧹 Cleaning cargo artifacts…${NC}"
    cargo clean
    echo -e "${GREEN}✅ target directory cleaned${NC}"
}

show_usage() {
    cat <<HELP
Usage: $0 [release|debug|test|clean] [build-mode]

release|prod   Build optimized ignite binary (default)
debug|dev      Build debug binary with symbols
test           Build then run cargo test
clean          Remove target artifacts
HELP
}

banner
check_age_installation

case "$BUILD_TYPE" in
    release|prod)
        build_release
        ;;
    debug|dev)
        build_debug
        ;;
    test)
        build_test
        ;;
    clean)
        clean_build
        ;;
    *)
        echo -e "${RED}❌ unknown build type: $BUILD_TYPE${NC}"
        show_usage
        exit 1
        ;;
esac

echo
TARGET_DIR="target/release"
if [[ "$BUILD_TYPE" == "debug" || "$BUILD_TYPE" == "dev" ]]; then
    TARGET_DIR="target/debug"
elif [[ "$BUILD_TYPE" == "test" ]]; then
    TARGET_DIR="target/debug"
fi

if [[ -f "$TARGET_DIR/ignite" ]]; then
    SIZE=$(du -h "$TARGET_DIR/ignite" | cut -f1)
    echo -e "${GREEN}📦 ignite binary: $TARGET_DIR/ignite ($SIZE)${NC}"
    echo -e "${YELLOW}Next steps:${NC}"
    echo -e "  • ./bin/deploy.sh                 # Install ignite into ~/.local/bin"
    echo -e "  • $TARGET_DIR/ignite --help        # Inspect CLI"
    echo -e "  • $TARGET_DIR/ignite proof --verify --all  # Proof sanity once wired"
else
    echo -e "${RED}❌ ignite binary missing in $TARGET_DIR${NC}"
    exit 1
fi

echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
