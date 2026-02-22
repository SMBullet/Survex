#!/usr/bin/env bash
# =============================================================================
# Survex — Full Setup Script
# =============================================================================
# Installs every dependency Survex needs, builds the binary and web UI,
# then delegates Go-tool installation to: ./survex install
#
# Supported platforms:
#   Linux  — Debian / Ubuntu / Kali (apt)
#   macOS  — Homebrew
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[✗]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

# ── Platform detection ────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux)
    if command -v apt-get &>/dev/null; then DISTRO="apt"
    else
      err "Unsupported Linux distribution — only apt-based systems are supported."
      err "Please install dependencies manually and re-run."
      exit 1
    fi
    ;;
  Darwin) DISTRO="brew" ;;
  *)
    err "Unsupported OS: $OS"
    exit 1
    ;;
esac

ok "Detected platform: $OS ($DISTRO)"

# ── Helper: check if a command exists ─────────────────────────────────────────
has() { command -v "$1" &>/dev/null; }

# ── Helper: apt install with minimal output ───────────────────────────────────
apt_install() {
  info "apt install: $*"
  sudo apt-get install -y -q "$@" 2>&1 | tail -3
}

# ── Helper: brew install ──────────────────────────────────────────────────────
brew_install() {
  info "brew install: $*"
  brew install "$@" 2>&1 | tail -3
}

# ── Helper: verify a version meets a minimum ─────────────────────────────────
# version_ge "1.21.5" "1.21" → true
version_ge() {
  [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -1)" = "$2" ]
}

# =============================================================================
# Step 1 — System update (Linux only)
# =============================================================================
if [ "$DISTRO" = "apt" ]; then
  section "Step 1: Update package index"
  info "Running apt-get update…"
  sudo apt-get update -q 2>&1 | tail -2
  ok "Package index updated."
else
  section "Step 1: Update Homebrew"
  brew update --quiet 2>&1 | tail -2 || true
  ok "Homebrew updated."
fi

# =============================================================================
# Step 2 — Go
# =============================================================================
section "Step 2: Go (≥ 1.22)"

NEED_GO=false
if has go; then
  GOVERSION="$(go version | awk '{print $3}' | sed 's/go//')"
  if version_ge "$GOVERSION" "1.22"; then
    ok "Go $GOVERSION already installed."
  else
    warn "Go $GOVERSION is too old (need ≥ 1.22) — upgrading."
    NEED_GO=true
  fi
else
  info "Go not found — installing."
  NEED_GO=true
fi

if [ "$NEED_GO" = "true" ]; then
  if [ "$DISTRO" = "apt" ]; then
    # Use the official tarball to guarantee a recent version.
    GO_VERSION="1.22.5"
    GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"
    info "Downloading Go $GO_VERSION from go.dev…"
    curl -fsSL "$GO_URL" -o "/tmp/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"
    # Make available in this session
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version | awk '{print $3}') installed to /usr/local/go."
    # Persist to common shell configs
    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile"; do
      [ -f "$RC" ] || continue
      grep -q '/usr/local/go/bin' "$RC" 2>/dev/null && continue
      printf '\n# Added by survex install.sh\nexport PATH="/usr/local/go/bin:$PATH"\n' >> "$RC"
      ok "Added Go to PATH in $RC"
    done
  else
    brew_install go
    ok "Go installed via Homebrew."
  fi
fi

# Ensure Go bin dir is in PATH for this session (survex install depends on it)
GOBIN="$(go env GOPATH)/bin"
export PATH="$GOBIN:$PATH"

# =============================================================================
# Step 3 — Node.js (≥ 18) and npm
# =============================================================================
section "Step 3: Node.js (≥ 18) + npm"

NEED_NODE=false
if has node; then
  NODEVERSION="$(node --version | sed 's/v//' | cut -d. -f1)"
  if [ "$NODEVERSION" -ge 18 ] 2>/dev/null; then
    ok "Node.js v$(node --version | sed 's/v//') already installed."
  else
    warn "Node.js v$(node --version) is too old (need ≥ 18) — upgrading."
    NEED_NODE=true
  fi
else
  info "Node.js not found — installing."
  NEED_NODE=true
fi

if [ "$NEED_NODE" = "true" ]; then
  if [ "$DISTRO" = "apt" ]; then
    # Use NodeSource for a recent LTS release
    info "Installing Node.js 20 LTS via NodeSource…"
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>&1 | tail -3
    apt_install nodejs
  else
    brew_install node
  fi
  ok "Node.js $(node --version) installed."
fi

if ! has npm; then
  warn "npm not found — installing…"
  if [ "$DISTRO" = "apt" ]; then apt_install npm; else brew_install npm; fi
fi
ok "npm $(npm --version) ready."

# =============================================================================
# Step 4 — System security tools (nmap, sqlmap)
# =============================================================================
section "Step 4: System tools (nmap, sqlmap)"

if has nmap; then
  ok "nmap $(nmap --version | head -1 | awk '{print $3}') already installed."
else
  info "Installing nmap…"
  if [ "$DISTRO" = "apt" ]; then apt_install nmap; else brew_install nmap; fi
  ok "nmap installed."
fi

if has sqlmap; then
  ok "sqlmap $(sqlmap --version 2>&1 | head -1) already installed."
else
  info "Installing sqlmap…"
  if [ "$DISTRO" = "apt" ]; then
    apt_install sqlmap
  else
    brew_install sqlmap
  fi
  ok "sqlmap installed."
fi

# =============================================================================
# Step 5 — Python 3 + pip3 + droopescan
# =============================================================================
section "Step 5: Python 3 + droopescan"

if ! has python3; then
  info "Installing Python 3…"
  if [ "$DISTRO" = "apt" ]; then apt_install python3 python3-pip; else brew_install python3; fi
fi
ok "Python $(python3 --version 2>&1 | awk '{print $2}') ready."

if ! has pip3; then
  if [ "$DISTRO" = "apt" ]; then apt_install python3-pip; else brew_install python3; fi
fi

if pip3 show droopescan &>/dev/null; then
  DROOP_VER="$(pip3 show droopescan 2>/dev/null | grep '^Version' | awk '{print $2}')"
  ok "droopescan $DROOP_VER already installed."
else
  info "Installing droopescan (Drupal/Joomla CMS scanner)…"
  pip3 install droopescan --quiet
  ok "droopescan installed."
fi

# =============================================================================
# Step 6 — Ruby + wpscan
# =============================================================================
section "Step 6: Ruby + wpscan"

if ! has ruby; then
  info "Installing Ruby…"
  if [ "$DISTRO" = "apt" ]; then apt_install ruby ruby-dev build-essential; else brew_install ruby; fi
fi
ok "Ruby $(ruby --version | awk '{print $2}') ready."

if ! has gem; then
  if [ "$DISTRO" = "apt" ]; then apt_install rubygems; fi
fi

# Ensure ruby gems bin is on PATH (macOS Homebrew Ruby)
if [ "$DISTRO" = "brew" ] && has brew; then
  RUBY_BIN="$(brew --prefix ruby)/bin"
  GEM_BIN="$(gem environment gemdir)/bin"
  export PATH="$RUBY_BIN:$GEM_BIN:$PATH"
fi

if has wpscan; then
  ok "wpscan $(wpscan --version 2>/dev/null | head -1) already installed."
else
  info "Installing wpscan (WordPress scanner)…"
  # --no-document skips ri/rdoc to speed things up
  sudo gem install wpscan --no-document 2>&1 | tail -5
  ok "wpscan installed."
fi

# =============================================================================
# Step 7 — Build Survex binary
# =============================================================================
section "Step 7: Build Survex"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "go.mod" ]; then
  err "go.mod not found — run this script from the Survex repository root."
  exit 1
fi

info "Downloading Go module dependencies…"
go mod download 2>&1 | tail -3

info "Building survex binary…"
go build -o survex ./cmd/survex/
ok "Survex binary built: $SCRIPT_DIR/survex"

# =============================================================================
# Step 8 — Install Go-based tools via ./survex install
# =============================================================================
section "Step 8: Install Go tools (via ./survex install)"

info "Running ./survex install — this installs subfinder, amass, httpx,"
info "gau, katana, gowitness, nuclei, ffuf, dalfox, and fixes PATH…"
echo ""

./survex install

# =============================================================================
# Step 9 — Update nuclei templates
# =============================================================================
section "Step 9: Update nuclei templates"

if has nuclei || [ -f "$GOBIN/nuclei" ]; then
  NUCLEI_BIN="nuclei"
  has nuclei || NUCLEI_BIN="$GOBIN/nuclei"
  info "Updating nuclei templates (may take a minute)…"
  "$NUCLEI_BIN" -update-templates -silent 2>&1 | tail -5 || \
    warn "Template update failed — run 'nuclei -update-templates' manually."
  ok "Nuclei templates updated."
else
  warn "nuclei not found in PATH yet — skipping template update."
  warn "After restarting your shell, run: nuclei -update-templates"
fi

# =============================================================================
# Step 10 — Build the Web UI
# =============================================================================
section "Step 10: Build web UI (Next.js)"

if [ -d "$SCRIPT_DIR/web" ] && [ -f "$SCRIPT_DIR/web/package.json" ]; then
  cd "$SCRIPT_DIR/web"

  info "Installing npm dependencies…"
  npm install --silent 2>&1 | tail -5

  info "Building Next.js frontend (output → web/out/)…"
  npm run build 2>&1 | tail -10

  cd "$SCRIPT_DIR"

  if [ -d "$SCRIPT_DIR/web/out" ]; then
    ok "Web UI built successfully → web/out/"
  else
    warn "Build finished but web/out/ was not created."
    warn "Check the Next.js config — ensure output: 'export' is set in next.config.ts."
  fi
else
  warn "web/ directory not found — skipping frontend build."
fi

# =============================================================================
# Summary
# =============================================================================
section "All done!"
echo ""
echo -e "${BOLD}Installed components:${RESET}"
echo -e "  ${GREEN}✓${RESET} Go tools       (subfinder, amass, httpx, gau, katana, gowitness, nuclei, ffuf, dalfox)"
echo -e "  ${GREEN}✓${RESET} System tools   (nmap, sqlmap)"
echo -e "  ${GREEN}✓${RESET} Python tools   (droopescan)"
echo -e "  ${GREEN}✓${RESET} Ruby tools     (wpscan)"
echo -e "  ${GREEN}✓${RESET} Survex binary  → ./survex"
echo -e "  ${GREEN}✓${RESET} Web UI         → web/out/"
echo ""
echo -e "${BOLD}Quick start:${RESET}"
echo ""
echo -e "  # CLI scan"
echo -e "  ${CYAN}./survex scan -t example.com -m all --client example${RESET}"
echo ""
echo -e "  # Web UI (builds and serves the dashboard)"
echo -e "  ${CYAN}./survex serve --frontend web/out${RESET}"
echo -e "  Then open: http://localhost:8080"
echo ""
echo -e "  # Check all tool statuses"
echo -e "  ${CYAN}./survex modules${RESET}"
echo ""
echo -e "${YELLOW}Note:${RESET} If Go tools aren't found, open a new terminal or run:"
echo -e "  ${CYAN}source ~/.bashrc${RESET}  (or ~/.zshrc on zsh)"
echo ""
