#!/usr/bin/env bash
set -euo pipefail

# --- Argument Parsing ---
SKIP_SETUP=false
ORGANIZATION=""
PASSTHRU_ARGS=()

# Use a while loop for robust argument parsing
# This loop will process all arguments, extracting --no-setup, the organization,
# and any other arguments to be passed down to setup.sh
TEMP_ARGS=("$@")
i=0
while [ $i -lt ${#TEMP_ARGS[@]} ]; do
  arg="${TEMP_ARGS[$i]}"
  case "$arg" in
    --no-setup)
      SKIP_SETUP=true
      ;;
    *)
      # The first non-flag argument is the organization
      if [ -z "$ORGANIZATION" ]; then
        ORGANIZATION=$arg
      else
        # All subsequent arguments are passed through
        PASSTHRU_ARGS+=("$arg")
      fi
      ;;
  esac
  i=$((i + 1))
done

# If ORGANIZATION is still not set after parsing args, prompt for it
if [ -z "$ORGANIZATION" ]; then
  read -r -p "Please enter the organization name for this scan: " ORGANIZATION
  if [ -z "$ORGANIZATION" ]; then
    echo "Error: Organization name cannot be empty." >&2
    exit 1
  fi
fi

OUTPUT_DIR="results/${ORGANIZATION}_$(date +%Y%m%d_%H%M%S)"
WORKDIR="$(pwd)"
VENV_DIR="$WORKDIR/.venv"

# --- Sudo / Setup Phase ---
if [ "$SKIP_SETUP" = false ]; then
  # If not root, re-exec with sudo, passing the determined organization and other args
  if [ "$(id -u)" -ne 0 ]; then
    echo "[run.sh] Elevating to sudo to perform initial system installs (you may be prompted for your password)."
    # We pass the organization and other args to the new script instance
    exec sudo bash "$0" "$ORGANIZATION" "${PASSTHRU_ARGS[@]}"
  fi

  # Now running as root; perform setup.sh (which is idempotent)
  echo "[run.sh] Running system bootstrap (setup.sh)..."
  bash setup.sh "${PASSTHRU_ARGS[@]}"

  # --- SURGICAL CORRECTION STARTS HERE ---
  # Ensure the system dependency for Selenium (chromedriver) is installed.
  echo "[run.sh] Ensuring chromium-driver is installed for Selenium..."
  apt-get update -y
  apt-get install -y chromium-driver
  # --- SURGICAL CORRECTION ENDS HERE ---

  # De-escalate and fix ownership.
  if [ -n "${SUDO_USER-}" ]; then
      echo "[run.sh] Fixing workspace permissions and dropping sudo privileges..."
      chown -R "$SUDO_USER" "$WORKDIR"
      # Re-execute the rest of the script as the original user, adding --no-setup
      # and passing the organization name and other args again.
      exec sudo -u "$SUDO_USER" bash "$0" --no-setup "$ORGANIZATION" "${PASSTHRU_ARGS[@]}"
  fi
fi

# --- Execution Phase (runs as the non-root user) ---

# If we are here, we are either the original user or have de-escalated.
# The rest of the script runs without sudo.

# Drop to an unprivileged context to run the orchestrator by creating/using a user 'orchestrator' if desired.
# For simplicity, we'll just continue as root but create/activate the venv and run master_recon.py
if [ ! -d "$VENV_DIR" ]; then
  echo "[run.sh] Virtualenv missing after setup; creating..."
  python3 -m venv "$VENV_DIR"
fi

# Activate venv for this shell's context
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# Explicitly use the venv pip to ensure requirements are met, hiding output
echo "[run.sh] Verifying Python dependencies..."
"$VENV_DIR/bin/pip" install -r requirements.txt >/dev/null

# basic preflight: check workflow_spec.json scripts/tools exist in PATH or workspace
echo "[run.sh] Performing preflight check against workflow_spec.json..."
if [ ! -f workflow_spec.json ]; then
  echo "[ERROR] workflow_spec.json not found in workspace. Aborting."
  exit 1
fi

MISSING=()
PYTHON=$(which python3 || true)
# parse JSON to extract script names
SCRIPTS=$(python3 - <<'PY'
import json
f=open('workflow_spec.json')
wf=json.load(f)
if isinstance(wf.get('workflow'), dict):
    stages = wf['workflow'].get('stages', [])
else:
    stages = wf.get('stages', [])
for st in stages or []:
    for s in st.get('scripts', []):
        name = (s or {}).get('name')
        if name:
            print(name)
PY
)

for s in $SCRIPTS; do
  # allow names with spaces by testing file existence in workspace or in PATH
  if [ -f "$WORKDIR/$s" ] || command -v "$s" >/dev/null 2>&1; then
    echo "  OK: $s"
    continue
  fi

  RESOLVED=$(python3 - "$WORKDIR" "$s" <<'PY'
import sys
from master_recon import resolve_script_path

workspace, target = sys.argv[1:3]
resolved = resolve_script_path(workspace, target)
if resolved:
    print(resolved)
PY
)

  if [ -n "$RESOLVED" ]; then
    echo "  OK: $s -> $RESOLVED"
  else
    echo "  MISSING: $s"
    MISSING+=("$s")
  fi
done

if [ ${#MISSING[@]} -ne 0 ]; then
  echo "\n[ERROR] The following scripts/tools referenced in workflow_spec.json are missing:\n"
  for m in "${MISSING[@]}"; do echo "  - $m"; done
  echo "\nPlease install or place these tools in the workspace."
  exit 1
fi

echo "[run.sh] All checks passed."

# Start the main workflow orchestrator
echo "[run.sh] Starting workflow orchestrator (master_recon.py)..."
python3 master_recon.py --output-dir "$OUTPUT_DIR" --organization "$ORGANIZATION"
