#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Survex — one-shot bootstrap installer
#
# Run once after git clone:
#   bash scripts/install.sh
#
# What it does:
#   1. Verifies Go >= 1.21 is installed
#   2. Builds the survex binary
#   3. Runs 'survex install' to install all missing Go tools and fix PATH
#   4. Runs a final 'survex modules' to show what's ready
#
# To only fix PATH without installing tools:
#   bash scripts/install.sh --fix-path
#
# To verify status without installing anything:
#   bash scripts/install.sh --check
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[✗]${RESET} $*"; }
section() { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Parse flags ───────────────────────────────────────────────────────────────
MODE="install"   # install | check | fix-path
for arg in "$@"; do
  case "$arg" in
    --check)     MODE="check" ;;
    --fix-path)  MODE="fix-path" ;;
    --help|-h)
      sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
  esac
done

# ── Resolve paths ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SURVEX_BIN="$PROJECT_DIR/survex"

# ── 1. Check Go ───────────────────────────────────────────────────────────────
section "Checking Go installation"

if ! command -v go &>/dev/null; then
  err "Go is not installed."
  echo "    Install it from: https://go.dev/dl/"
  echo "    Then re-run this script."
  exit 1
fi

GO_VER_FULL=$(go version | awk '{print $3}')          # e.g. go1.22.3
GO_VER="${GO_VER_FULL#go}"                             # e.g. 1.22.3
GO_MAJOR="${GO_VER%%.*}"                               # e.g. 1
GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)              # e.g. 22

if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 21 ]; }; then
  err "Go 1.21+ required (found $GO_VER_FULL)"
  echo "    Upgrade at: https://go.dev/dl/"
  exit 1
fi

ok "Go $GO_VER found at $(command -v go)"

# ── 2. Build survex ───────────────────────────────────────────────────────────
section "Building survex"

cd "$PROJECT_DIR"
go build -o survex ./cmd/survex/
ok "survex binary built: $SURVEX_BIN"

# ── 3. Install / check tools ──────────────────────────────────────────────────
section "External tools"

case "$MODE" in
  check)
    "$SURVEX_BIN" install --check
    ;;
  fix-path)
    "$SURVEX_BIN" install --fix-path
    ;;
  install)
    "$SURVEX_BIN" install
    ;;
esac

# ── 4. Python tools (prowler) ─────────────────────────────────────────────────
section "Python tools"

# prowler is a pip package and cannot be auto-installed by 'survex install'.
# Install it here so cloud configuration reviews work out of the box.
_pip_install_prowler() {
  if command -v pipx &>/dev/null; then
    pipx install prowler --quiet
    export PATH="$HOME/.local/bin:$PATH"
    ok "prowler installed via pipx."
  elif pip3 install prowler --quiet --break-system-packages 2>/dev/null; then
    ok "prowler installed."
  elif pip3 install prowler --quiet --user 2>/dev/null; then
    export PATH="$HOME/.local/bin:$PATH"
    ok "prowler installed (user scheme)."
  else
    warn "Could not install prowler automatically."
    warn "Install manually: pip install prowler"
  fi
}

if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
  PIP_CMD="pip3"; command -v pip3 &>/dev/null || PIP_CMD="pip"
  if $PIP_CMD show prowler &>/dev/null 2>&1 || command -v prowler &>/dev/null; then
    PROWLER_VER="$($PIP_CMD show prowler 2>/dev/null | grep '^Version' | awk '{print $2}')"
    ok "prowler ${PROWLER_VER:-already} installed."
  else
    warn "prowler not found — installing (multi-cloud security audit)…"
    _pip_install_prowler
  fi
else
  warn "pip not found — skipping prowler install."
  warn "Install Python 3 + pip, then run: pip install prowler"
fi

# ── 5. System tools reminder ──────────────────────────────────────────────────
section "System tools (require manual install)"

NMAP_OK=false
command -v nmap &>/dev/null && NMAP_OK=true

if ! $NMAP_OK; then
  warn "nmap is not installed (needed for port scanning):"
  if command -v apt-get &>/dev/null; then
    echo "    sudo apt install -y nmap"
  elif command -v brew &>/dev/null; then
    echo "    brew install nmap"
  elif command -v pacman &>/dev/null; then
    echo "    sudo pacman -S nmap"
  else
    echo "    https://nmap.org/download.html"
  fi
else
  ok "nmap: $(nmap --version | head -1)"
fi

# ── 6. Final module overview ──────────────────────────────────────────────────
section "Module status"
"$SURVEX_BIN" modules

# ── 7. Quick-start hint ───────────────────────────────────────────────────────
echo ""
ok "Bootstrap complete."
echo ""
echo "  Quick-start:"
echo "    # Scan a single host (no subdomain enumeration)"
echo "    $SURVEX_BIN scan -t example.com -m \"httpx,headers,cors,cookies,nuclei\" --no-subs --client test"
echo ""
echo "    # Full scan with subdomain discovery"
echo "    $SURVEX_BIN scan -t example.com -m all --client test"
echo ""
if [ "$MODE" = "install" ]; then
  GOBIN="$HOME/go/bin"
  CURRENT_PATH="${PATH:-}"
  if [[ ":$CURRENT_PATH:" != *":$GOBIN:"* ]]; then
    warn "~/go/bin is not in your current PATH."
    warn "Run one of the following to apply it now:"
    echo "    source ~/.bashrc"
    echo "    source ~/.zshrc"
    echo "    export PATH=\"$GOBIN:\$PATH\""
  fi
  echo "  To make survex available system-wide:"
  echo "    sudo cp $SURVEX_BIN /usr/local/bin/survex"
fi
