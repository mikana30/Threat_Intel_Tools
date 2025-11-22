#!/usr/bin/env python3
"""
Deep cleanup: wipe all results from previous runs.
- Uses workflow_spec.json to find every stage output
- Removes all run-specific artifacts (outputs, logs, recon per-domain files)
- Preserves inputs (requirements.txt, targets*.txt, .py scripts, .venv)
"""

import os
import glob
import json
import shutil

WORKFLOW_SPEC = "workflow_spec.json"

SAFE_KEEP = ["requirements.txt"]
SAFE_PATTERNS = ["targets*.txt", "*.py", ".venv"]

def is_safe(path: str) -> bool:
    base = os.path.basename(path)
    if base in SAFE_KEEP:
        return True
    for pat in SAFE_PATTERNS:
        if glob.fnmatch.fnmatch(base, pat):
            return True
    return False

def load_generated_patterns(spec_path: str):
    patterns = []
    if not os.path.exists(spec_path):
        print(f"[!] Spec file {spec_path} not found, falling back to defaults.")
        return patterns

    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)

    for stage in spec.get("stages", []):
        for script in stage.get("scripts", []):
            for flag in script.get("flags", []):
                if isinstance(flag, str) and (
                    flag.startswith("outputs/") or flag.startswith("clean_")
                    or flag.endswith(".txt") or flag.endswith(".csv") or flag.endswith(".json")
                ):
                    patterns.append(flag)

    # Add the entire outputs and logs directories for a full wipe
    patterns.append("outputs")
    patterns.append("logs")

    # Recon1 known artifacts
    recon_patterns = [
        "*/subdomz.txt", "*/assetfinder.txt", "*/subfinder.txt", "*/gau.txt",
        "*/httpx_input.txt", "*/httpx_output.txt", "*/all_domains.txt", "*/*_recon.csv"
    ]
    patterns.extend(recon_patterns)

    return sorted(set(patterns))

def cleanup():
    root = os.getcwd()
    patterns = load_generated_patterns(WORKFLOW_SPEC)

    print(f"[*] Deep cleanup in {root}")
    for pattern in patterns:
        # --- DEBUG LINE ADDED ---
        print(f"[*] Processing pattern: {pattern}")
        # --- END OF CHANGE ---
        # Use glob to find all matching paths, including directories
        for path in glob.glob(pattern, recursive=True):
            if is_safe(path):
                continue
            if os.path.isdir(path):
                print(f"[-] Removing directory: {path}")
                shutil.rmtree(path, ignore_errors=True)
            else:
                print(f"[-] Removing file: {path}")
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
                except Exception as e:
                    print(f"[!] Error deleting {path}: {e}")
    print("[*] Old results wiped. Fresh run ready...")

if __name__ == "__main__":
    cleanup()
