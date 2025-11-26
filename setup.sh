#!/usr/bin/env bash
set -euo pipefail

# Full bootstrap for Threat-Intel Orchestrator (fat bundle)
# - Installs apt packages, Go, pip deps
# - Installs common recon tools used by workflow_spec.json
# - Creates Python venv and installs requirements
# - Places binaries in /usr/local/bin (requires sudo)
#
# Idempotent: safe to run multiple times.

WORKDIR="$(pwd)"
VENV_DIR="$WORKDIR/.venv"

# Require root for system installs; self-elevate if needed
if [ "$(id -u)" -ne 0 ]; then
  echo "[setup.sh] This script must run as root. Re-running with sudo..."
  exec sudo bash "$0" "$@"
fi

# Detect platform
if grep -qi microsoft /proc/version; then
    PLATFORM="wsl"
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" = "kali" ]; then
        PLATFORM="kali"
    else
        PLATFORM="linux"
    fi
else
    PLATFORM="unknown"
fi
echo "Detected platform: $PLATFORM"

export DEBIAN_FRONTEND=noninteractive

echo "[*] Updating apt and installing base packages..."
apt update -y
apt install -y --no-install-recommends \
  git ca-certificates curl wget unzip jq \
  build-essential gcc make cmake pkg-config \
  python3 python3-venv python3-pip \
  libpcap-dev libssl-dev zlib1g-dev libbz2-dev liblzma-dev \
  chromium chromium-driver nmap whois whatweb

# ----------------------------
# Install Go if missing
# ----------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "[*] Installing Go 1.21..."
  GO_VER="1.23.3"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) GO_ARCH="linux-amd64" ;;
    aarch64|arm64) GO_ARCH="linux-arm64" ;;
    *)
      echo "Unsupported arch: $ARCH"
      exit 1
      ;;
  esac

  # Run directory changes in a subshell to not affect the main script's CWD
  (
    TMP="/tmp/go_install"
    mkdir -p "$TMP"
    cd "$TMP"
    wget "https://golang.org/dl/go${GO_VER}.${GO_ARCH}.tar.gz" -O go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go.tar.gz
    rm -rf "$TMP"
  )
fi

# Ensure Go is usable in this session (not just future shells)
export PATH="/usr/local/go/bin:$PATH"
export GOPATH="${GOPATH:-/root/go}"
mkdir -p "$GOPATH/bin"

# Persist for future shells (optional)
if ! grep -q '/usr/local/go/bin' /etc/profile; then
  echo 'export PATH=/usr/local/go/bin:$PATH' >> /etc/profile
  echo 'export GOPATH=${GOPATH:-$HOME/go}' >> /etc/profile
fi

# ----------------------------
# Python venv + pip deps
# ----------------------------
if [ ! -d "$VENV_DIR" ]; then
  echo "[*] Creating Python venv at $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi

echo "[*] Installing Python dependencies into venv..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel setuptools
"$VENV_DIR/bin/pip" install -r requirements.txt

# Check GLIBC version (Go binaries need 2.17+)
GLIBC_VERSION=$(ldd --version | head -n1 | grep -oP '\d+\.\d+$')
echo "GLIBC version: $GLIBC_VERSION"

# ----------------------------
# Install Go-based recon tools
# ----------------------------
echo "[*] Installing Go reconnaissance tools into /usr/local/bin..."

install_go_tool () {
  local pkg="$1" bin_name="$2"
  if ! command -v "$bin_name" >/dev/null 2>&1; then
    echo "  - installing $bin_name..."
    go install "$pkg@latest"
    # Prefer GOPATH/bin, fallback to go env GOPATH
    local src="$GOPATH/bin/$bin_name"
    if [ ! -f "$src" ]; then
      src="$(go env GOPATH)/bin/$bin_name"
    fi
    if [ -f "$src" ]; then
      cp "$src" /usr/local/bin/
      chmod +x "/usr/local/bin/$bin_name"
    else
      echo "    ! failed to locate built binary for $bin_name after go install"
      return 1
    fi
  else
    echo "  - $bin_name already present"
  fi
}

install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
install_go_tool "github.com/owasp-amass/amass/v3/... " "amass" || true
install_go_tool "github.com/tomnomnom/assetfinder" "assetfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
install_go_tool "github.com/lc/gau/v2/cmd/gau" "gau"
install_go_tool "github.com/sensepost/gowitness" "gowitness"

# ----------------------------
# Optional extra Python tooling (best-effort)
# ----------------------------

# The following was originally included, but the repo is no longer accessible:
# pip install git+https://github.com/joepie91/pydnstools.git@master || true
#
# Leaving it commented out avoids noisy errors during setup,
# but keeps the reference here for clarity.

# ----------------------------
# Keys/targets conveniences
# ----------------------------
if [ ! -f "$WORKDIR/keys.json" ]; then
  if [ -f "$WORKDIR/keys.json.example" ]; then
    cp "$WORKDIR/keys.json.example" "$WORKDIR/keys.json"
    echo "  -> Created keys.json from template. Fill in API keys as needed."
  else
    cat > "$WORKDIR/keys.json" <<'JSON'
{
  "abuseipdb": "",
  "shodan": "",
  "virustotal": "",
  "securitytrails": ""
}
JSON
    echo "  -> Created default keys.json (empty values)."
  fi
fi

if [ ! -f "$WORKDIR/targets.txt" ]; then
  echo "example.com" > "$WORKDIR/targets.txt"
  echo "  -> Created placeholder targets.txt (replace with your domains)."
fi

echo "[*] Setup complete. You can now run the orchestrator using run.sh."
