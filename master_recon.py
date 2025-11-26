#!/usr/bin/env python3
import argparse
import json
import os
import sys
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import dev_mode
import yaml

# Import utilities
try:
    from utils.resource_checks import check_disk_space
except ImportError as e:
    print(f"FATAL: utils.resource_checks module not available: {e}", file=sys.stderr)
    print("Ensure you are running from the workspace root:", file=sys.stderr)
    print("  cd /home/mikana/Threat_Intel_Tools", file=sys.stderr)
    print("  python3 master_recon.py [args]", file=sys.stderr)
    sys.exit(1)

# --- Logging Setup ---
# Each script will configure its own logging.
# ---------------------

# ---------------------------
# Helpers (robust resolver - unchanged)
# ---------------------------

def resolve_script_path(workspace: str, name: str) -> str | None:
    """
    Resolve a script name to an actual executable path.

    Strategy:
    1) Exact file under workspace (accept plain files; .py run via python).
    2) Case/space-insensitive match anywhere directly under workspace.
    3) PATH lookup (exact, then exec bit).
    Returns absolute path or None.
    """
    if not name:
        return None

    # Get real workspace path for traversal checks
    workspace_real = os.path.realpath(workspace)

    # 1) Exact file in workspace
    candidate = os.path.join(workspace, name)
    if os.path.isfile(candidate):
        # Check for path traversal
        resolved = os.path.realpath(candidate)
        if not resolved.startswith(workspace_real + os.sep):
            logging.warning(f"Path traversal attempt blocked: {name}")
            return None
        return os.path.abspath(candidate)

    # 2) Case/space-insensitive match on files in workspace (non-recursive)
    target_norm = name.replace(" ", "").lower()
    try:
        for f in os.listdir(workspace):
            fp = os.path.join(workspace, f)
            if os.path.isfile(fp):
                if f.replace(" ", "").lower() == target_norm:
                    # Check for path traversal
                    resolved = os.path.realpath(fp)
                    if not resolved.startswith(workspace_real + os.sep):
                        logging.warning(f"Path traversal attempt blocked: {name}")
                        return None
                    return os.path.abspath(fp)
    except FileNotFoundError:
        pass # Workspace might not exist yet, handled by caller

    # 3) PATH lookup (exact file name as given)
    for p in os.environ.get('PATH', '').split(os.pathsep):
        cand = os.path.join(p, name)
        # Check if it exists and is either a file or executable
        if (os.path.isfile(cand) or os.access(cand, os.X_OK)) and not os.path.isdir(cand):
             return os.path.abspath(cand)

    return None

# ---------------------------
# Core
# ---------------------------

def run_script(script_path: str, flags: list[str], workspace: str):
    """
    Run a single script (Python or binary). stdout/stderr captured and returned.
    Logs start, completion, and errors.
    """
    script_name = os.path.basename(script_path) if script_path else "<unknown_script>"

    if script_path is None:
        logging.error(f"Script '{script_name}' could not be resolved to a path.")
        return (script_name, "not-found", "", "resolver returned None")

    # If it's a .py, run with the current interpreter; otherwise run directly
    if script_path.lower().endswith(".py"):
        cmd = [sys.executable, script_path] + (flags or [])
    else:
        # Ensure script is executable if not running via interpreter
        if not os.access(script_path, os.X_OK):
             try:
                 # Attempt to make it executable
                 os.chmod(script_path, os.stat(script_path).st_mode | 0o111) # Add execute perm
                 logging.debug(f"Made script executable: {script_path}")
             except Exception as chmod_err:
                 logging.error(f"Failed to make script executable '{script_name}' at {script_path}: {chmod_err}")
                 return (script_name, "not-executable", "", str(chmod_err))

        cmd = [script_path] + (flags or [])

    cmd_str = " ".join(cmd) # For logging purposes
    logging.info(f"Starting script: {script_name}...")
    logging.debug(f"Executing command: {cmd_str} in {workspace}")
    start_time = time.time()

    try:
        # Use Popen and communicate to safely capture all output without deadlocking
        with subprocess.Popen(cmd, cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore') as process:
            stdout, stderr = process.communicate()
            retcode = process.poll()
            duration = time.time() - start_time

            if retcode != 0:
                logging.error(f"Script '{script_name}' failed with code {retcode} after {duration:.2f}s.")
                # Log stderr if it's not empty
                if stderr:
                    logging.error(f"Stderr from {script_name}:\n{stderr.strip()}")
                return (script_name, f"failure:{retcode}", stdout or "", stderr or "")

            logging.info(f"Script '{script_name}' finished successfully in {duration:.2f}s.")
            logging.debug(f"Stdout from {script_name}:\n{stdout.strip()}")
            if stderr: # Log stderr even on success, but maybe as warning or debug
                 logging.warning(f"Stderr from {script_name} (exit code 0):\n{stderr.strip()}")

            return (script_name, "success", stdout, stderr)

    except FileNotFoundError:
         logging.error(f"Script '{script_name}' command not found: {cmd[0]}")
         return (script_name, "cmd-not-found", "", f"Command not found: {cmd[0]}")
    except PermissionError:
         logging.error(f"Permission denied executing script '{script_name}': {cmd[0]}")
         return (script_name, "permission-denied", "", f"Permission denied: {cmd[0]}")
    except Exception as e:
        duration = time.time() - start_time
        logging.exception(f"An unexpected error occurred running script '{script_name}' after {duration:.2f}s: {e}") # Use logging.exception to include traceback
        return (script_name, "error", "", str(e))

def install_missing_dependency(dep_type: str, name: str, workspace: str) -> bool:
    """
    Attempt to install a missing dependency.
    Returns True if successful, False otherwise.
    """
    try:
        if dep_type == 'python_package':
            logging.info(f"Installing Python package: {name}...")
            # Try pip with --break-system-packages for Kali/Debian systems
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', name, '--break-system-packages'],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                logging.info(f"Successfully installed {name}")
                return True
            else:
                logging.warning(f"Failed to install {name}: {result.stderr}")
                return False

        elif dep_type == 'subdomz':
            logging.info("Installing SubDomz.sh...")
            # Clone and install SubDomz
            temp_dir = os.path.join(workspace, 'temp_subdomz_install')
            result = subprocess.run(
                ['git', 'clone', 'https://github.com/0xPugazh/SubDomz.git', temp_dir],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                import shutil
                src = os.path.join(temp_dir, 'SubDomz.sh')
                dst = os.path.join(workspace, 'SubDomz.sh')
                shutil.copy2(src, dst)
                os.chmod(dst, 0o755)
                shutil.rmtree(temp_dir)
                logging.info("Successfully installed SubDomz.sh")
                return True
            else:
                logging.warning(f"Failed to install SubDomz: {result.stderr}")
                return False

    except Exception as e:
        logging.error(f"Error installing {name}: {e}")
        return False

def check_external_tools(workspace: str, auto_install: bool = True) -> dict:
    """
    Check for required external tools (recon tools, chromedriver, etc.)
    If auto_install is True, attempt to install missing dependencies.
    Returns dict with 'missing' and 'warnings' lists.
    """
    logging.info("Checking external tool dependencies...")
    result = {'missing': [], 'warnings': [], 'installed': []}

    # Check Python packages first (easiest to install)
    required_packages = ['selenium', 'requests', 'tqdm', 'pandas', 'yaml', 'webdriver-manager', 'portalocker', 'python-docx']
    packages_to_install = []

    for package in required_packages:
        try:
            __import__(package)
            logging.debug(f"Python package check OK: {package}")
        except ImportError:
            packages_to_install.append(package)

    # Auto-install missing Python packages
    if packages_to_install and auto_install:
        logging.info(f"Installing {len(packages_to_install)} missing Python packages...")
        for package in packages_to_install:
            if install_missing_dependency('python_package', package, workspace):
                result['installed'].append(f"Python package: {package}")
            else:
                result['warnings'].append(f"Python package '{package}' not installed (installation failed)")

    # Check recon tools from config/recon.yml
    recon_config_path = os.path.join(workspace, 'config', 'recon.yml')
    if os.path.exists(recon_config_path):
        try:
            with open(recon_config_path, 'r') as f:
                recon_config = yaml.safe_load(f)

            modules = recon_config.get('modules', {})
            for tool_name, config in modules.items():
                if config.get('enabled', False):
                    # Check if tool is in PATH or as specified path
                    tool_path = config.get('path')
                    if tool_path:
                        # Relative path specified (e.g., SubDomz.sh)
                        full_path = os.path.join(workspace, tool_path)
                        if not os.path.exists(full_path):
                            if auto_install and tool_name == 'subdomz':
                                if install_missing_dependency('subdomz', tool_name, workspace):
                                    result['installed'].append(f"Recon tool: {tool_name}")
                                else:
                                    result['warnings'].append(f"{tool_name}: {tool_path} not found (installation failed)")
                            else:
                                result['warnings'].append(f"{tool_name}: {tool_path} not found (will be skipped)")
                        else:
                            logging.debug(f"External tool check OK: {tool_name} at {full_path}")
                    else:
                        # Check PATH
                        if not resolve_script_path(workspace, tool_name):
                            result['warnings'].append(f"{tool_name}: not found in PATH (will be skipped)")
                        else:
                            logging.debug(f"External tool check OK: {tool_name}")
        except Exception as e:
            logging.warning(f"Could not check recon tools: {e}")

    # Check for other critical tools
    critical_tools = {
        'httpx': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'chromedriver': 'See screenshot_service.py for auto-install',
        'whatweb': 'sudo apt install whatweb',
    }

    for tool, install_hint in critical_tools.items():
        if not resolve_script_path(workspace, tool):
            result['warnings'].append(f"{tool}: not found - Install: {install_hint}")
            result['missing'].append(tool)
        else:
            logging.debug(f"External tool check OK: {tool}")

    # Report results
    if result['installed']:
        logging.info(f"Successfully installed {len(result['installed'])} dependencies:")
        for installed in result['installed']:
            logging.info(f"  ✓ {installed}")

    if result['warnings']:
        logging.warning(f"External tool check found {len(result['warnings'])} warnings:")
        for warning in result['warnings']:
            logging.warning(f"  - {warning}")
    else:
        logging.info("External tool check passed: All dependencies available.")

    # Return validation status (True if no critical tools are missing)
    validation_passed = len(result['missing']) == 0
    result['validation_passed'] = validation_passed

    return result

def preflight_check(workflow: dict, workspace: str) -> list[str]:
    """
    Verify every script in the workflow resolves to a path (using resolver).
    Also check external tool dependencies.
    Returns sorted list of any missing names.
    """
    logging.info("Starting preflight check...")
    missing = []
    scripts_to_check = set() # Use a set to avoid duplicate checks

    for st in workflow.get('stages', []):
        for s in st.get('scripts', []):
            name = (s or {}).get('name', '')
            if name:
                scripts_to_check.add(name)

    if not scripts_to_check:
        logging.warning("Workflow specification has no scripts defined.")
        return []

    for name in scripts_to_check:
        resolved_path = resolve_script_path(workspace, name)
        if resolved_path is None:
            logging.error(f"Preflight check failed: Script '{name}' not found in workspace or PATH.")
            missing.append(name)
        else:
            logging.debug(f"Preflight check OK: '{name}' resolved to '{resolved_path}'")

    if not missing:
        logging.info("Preflight check passed: All scripts resolved.")
    else:
        logging.error("Preflight check failed: Some scripts could not be found.")

    # Check external tools
    tool_check = check_external_tools(workspace)
    if tool_check['warnings']:
        logging.critical("=== CRITICAL TOOLS MISSING ===")
        for warning in tool_check['warnings']:
            logging.critical(f"  - {warning}")
        logging.critical("These tools are REQUIRED for workflow execution.")
        logging.critical("Run setup.sh or install missing tools manually.")
        sys.exit(1)

    return sorted(missing)

def run_stage(stage: dict, workspace: str, threads: int, dry_run: bool, output_dir: str):
    """
    Run all scripts listed in a stage (concurrently or serially based on threads).
    Logs stage start/end and individual script results.
    """
    stage_id = stage.get('id', 'N/A')
    stage_name = stage.get('name', 'Unnamed Stage')
    scripts = stage.get("scripts", [])

    logging.info(f"--- Starting Stage {stage_id}: {stage_name} ---")
    stage_start_time = time.time()

    if not scripts:
        logging.warning(f"Stage {stage_id}: {stage_name} has no scripts defined. Skipping.")
        return []

    results = []
    # Resolve all paths up front
    jobs = []
    for s in scripts:
        sname = s.get("name", "")
        if not sname:
            logging.warning(f"Found script entry with no name in stage {stage_id}, skipping.")
            continue
        
        sflags = s.get("flags", []) or []
        sflags_processed = [flag.replace('{output_dir}', output_dir) for flag in sflags]
        
        spath = resolve_script_path(workspace, sname)
        jobs.append((sname, spath, sflags_processed))

    if dry_run:
        logging.info(f"Dry run for Stage {stage_id}: {stage_name}")
        for sname, spath, sflags in jobs:
            flags_str = " ".join(sflags)
            if spath:
                logging.info(f"[DRY-RUN] Would run: {spath} {flags_str}")
            else:
                logging.warning(f"[DRY-RUN] Script '{sname}' NOT FOUND. Would fail.")
        logging.info(f"--- Finished Dry Run for Stage {stage_id}: {stage_name} ---")
        return [] # Return empty list for dry run

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        # Dictionary to map futures back to script names for logging
        future_to_script = {ex.submit(run_script, spath, sflags, workspace): sname
                            for (sname, spath, sflags) in jobs}

        for future in as_completed(future_to_script):
            script_name_completed = future_to_script[future]
            try:
                result = future.result()
                results.append(result)
                # Logging for individual script completion is handled within run_script
            except Exception as exc:
                # This catches errors *during* the future execution itself, less common now
                logging.exception(f"Exception raised by script '{script_name_completed}' execution: {exc}")
                results.append((script_name_completed, "future-error", "", str(exc)))

    stage_duration = time.time() - stage_start_time
    logging.info(f"--- Finished Stage {stage_id}: {stage_name} in {stage_duration:.2f}s ---")
    return results

def main():
    # Validate workspace root
    workspace = os.getcwd()
    if not os.path.exists(os.path.join(workspace, 'workflow_spec.json')):
        print("ERROR: Must run from Threat_Intel_Tools directory")
        print(f"Current directory: {workspace}")
        sys.exit(1)

    # Quick dependency check (unless explicitly skipped)
    if not os.getenv("SKIP_DEPENDENCY_CHECK"):
        try:
            sys.path.insert(0, workspace)
            from check_dependencies import check_and_install_dependencies

            # Auto-install mode if running non-interactively
            auto_install = not sys.stdin.isatty()

            if not check_and_install_dependencies(auto_install=auto_install):
                print("\nWARNING: Some dependencies are missing.", file=sys.stderr)
                print("The workflow may fail or have limited functionality.", file=sys.stderr)

                if sys.stdin.isatty():
                    response = input("\nContinue anyway? [y/N]: ").strip().lower()
                    if response not in ['y', 'yes']:
                        print("Aborted. Run 'python3 utils/dependency_manager.py' to install dependencies.")
                        sys.exit(1)
                else:
                    # In non-interactive mode, continue with warning
                    print("Continuing in non-interactive mode...", file=sys.stderr)

            print()  # Blank line for readability
        except Exception as e:
            print(f"WARNING: Dependency check failed: {e}", file=sys.stderr)
            print("Continuing anyway... some functionality may be unavailable.", file=sys.stderr)
            print()

    ap = argparse.ArgumentParser(description="Threat intel workflow orchestrator")
    ap.add_argument("--spec", default="workflow_spec.json", help="Path to workflow_spec.json")
    ap.add_argument("--organization", default="SCAN", help="Name of the organization for the output directory")
    ap.add_argument("--threads", type=int, default=2, help="Parallelism within a stage")
    ap.add_argument("--dry-run", action="store_true", help="Print what would run instead of executing")
    ap.add_argument("--verbose", "-v", action='store_true', help="Enable DEBUG level logging")
    ap.add_argument("--start-stage", type=str, help="Start execution from a specific stage ID.")
    ap.add_argument("--output-dir", help="Use an existing output directory instead of creating a new one.")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    # Interactive mode selection if not specified via environment
    # Load environment settings
    env_settings = dev_mode.load_env_settings()

    # Only prompt if not running in background and no environment override
    if not args.dry_run and sys.stdin.isatty() and not os.getenv("TI_MODE"):
        print("\n" + "="*60)
        print("  WORKFLOW EXECUTION MODE")
        print("="*60)
        print("\nSelect execution mode:")
        print("  [1] DEV mode      - 100 target cap (fast validation, ~5-10 min)")
        print("  [2] QUICK mode    - 1000 target cap (performance testing, ~15-30 min)")
        print("  [3] PRODUCTION mode - No limits (full scan, hours)")
        print("\nCurrent config: mode = " + env_settings.get('mode', 'production'))

        while True:
            try:
                choice = input("\nEnter choice [1-3] (or press Enter for current config): ").strip()

                if choice == '':
                    # Use config file setting
                    selected_mode = env_settings.get('mode', 'production')
                    break
                elif choice == '1':
                    selected_mode = 'dev'
                    break
                elif choice == '2':
                    selected_mode = 'quick'
                    break
                elif choice == '3':
                    selected_mode = 'production'
                    break
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
            except (EOFError, KeyboardInterrupt):
                print("\nAborted by user.")
                sys.exit(0)

        # Update environment settings for this run
        env_settings['mode'] = selected_mode

        # Show selected mode
        mode_caps = {
            'dev': '100 targets',
            'quick': '1000 targets',
            'production': 'unlimited'
        }
        print(f"\nSelected: {selected_mode.upper()} mode ({mode_caps[selected_mode]})")
        print("="*60 + "\n")

        # Temporarily write the mode to environment for this process
        os.environ['TI_MODE'] = selected_mode

    # Check for updates (if not disabled)
    if not args.dry_run and os.getenv('TI_AUTO_UPDATE') != 'disabled':
        try:
            auto_update_script = os.path.join(os.getcwd(), 'auto_update.py')
            if os.path.exists(auto_update_script):
                subprocess.run([sys.executable, auto_update_script], check=False)
        except Exception as e:
            logging.warning(f"Auto-update check failed: {e}")

    logging.info("Workflow orchestrator started.")
    workspace = os.getcwd()
    logging.debug(f"Workspace directory: {workspace}")

    # --- Determine output directory ---
    if args.output_dir:
        output_dir_name = args.output_dir
        output_dir_path = os.path.join(workspace, output_dir_name)
        logging.info(f"Using existing output directory: {output_dir_path}")
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir_name = f"results/{args.organization}_{timestamp}"
        output_dir_path = os.path.join(workspace, output_dir_name)
        logging.info(f"Created new output directory: {output_dir_path}")

    raw_outputs_dir = os.path.join(output_dir_path, "raw_outputs")
    processed_files_dir = os.path.join(output_dir_path, "processed_files")

    # Check disk space before creating directories
    try:
        check_disk_space(workspace, min_gb=10)
        logging.info("Disk space check passed")
    except IOError as e:
        logging.critical(f"Disk space check failed: {e}")
        sys.exit(1)

    try:
        os.makedirs(raw_outputs_dir, exist_ok=True)
        os.makedirs(processed_files_dir, exist_ok=True)
    except OSError as e:
        logging.critical(f"Failed to create output subdirectories: {e}")
        sys.exit(1)

    # Load workflow spec
    spec_path = os.path.join(workspace, args.spec)
    if not os.path.isfile(spec_path):
        logging.critical(f"Workflow specification file not found: {spec_path}")
        sys.exit(1)

    try:
        with open(spec_path, "r", encoding="utf-8") as fh:
            wf_root = json.load(fh)
        workflow = wf_root.get("workflow", wf_root)
        logging.info(f"Loaded workflow specification from: {spec_path}")
    except json.JSONDecodeError as e:
        logging.critical(f"Error decoding JSON from {spec_path}: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred loading {spec_path}: {e}")
        sys.exit(1)

    # Preflight Check
    missing_scripts = preflight_check(workflow, workspace)
    if missing_scripts:
        logging.critical("Preflight check failed. Exiting.")
        sys.exit(1)

    # Run workflow stages
    all_results = []
    workflow_stages = workflow.get("stages", [])
    if not workflow_stages:
        logging.warning("No stages found in the workflow specification.")
        return

    start_index = 0
    if args.start_stage:
        found_start_stage = False
        for i, stage in enumerate(workflow_stages):
            if str(stage.get('id')) == args.start_stage:
                start_index = i
                found_start_stage = True
                logging.info(f"Starting workflow from stage {args.start_stage}: {stage.get('name')}")
                break
        if not found_start_stage:
            logging.critical(f"Specified start stage '{args.start_stage}' not found in workflow.")
            sys.exit(1)

    logging.info(f"Starting execution of {len(workflow_stages) - start_index} stages (from stage {workflow_stages[start_index].get('id')})...")
    for i, stage in enumerate(workflow_stages[start_index:]):
        stage_id = stage.get('id', f'stage_{start_index + i + 1}')
        stage['id'] = stage_id
        stage_results = run_stage(stage, workspace, args.threads, args.dry_run, output_dir_name)
        all_results.extend(stage_results)

        failures = [res for res in stage_results if res[1] != "success"]
        if failures:
            logging.error(f"Stage {stage_id} completed with {len(failures)} failures.")
        else:
             logging.info(f"Stage {stage_id} completed successfully.")

    logging.info("Workflow execution finished.")

    final_errors = [r for r in all_results if r[1] != 'success']
    if final_errors:
        logging.error(f"Workflow completed with {len(final_errors)} total errors/failures.")
    elif not args.dry_run:
        logging.info("Workflow completed successfully with no errors.")

if __name__ == "__main__":
    main()
