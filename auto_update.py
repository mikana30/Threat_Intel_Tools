#!/usr/bin/env python3
"""
Auto-update checker for threat intel workflow
Checks for updates from git remote and prompts user to update
"""
import subprocess
import sys
import os

def run_command(cmd, check=False):
    """Run shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr

def check_for_updates():
    """Check if updates are available from git remote"""

    # Check if we're in a git repository
    ret, _, _ = run_command("git rev-parse --git-dir")
    if ret != 0:
        print("⚠️  Not a git repository. Skipping update check.")
        return False

    # Check if remote is configured
    ret, remote, _ = run_command("git remote")
    if ret != 0 or not remote:
        print("⚠️  No git remote configured. Skipping update check.")
        print("   To enable auto-updates, add a remote:")
        print("   git remote add origin <your-repo-url>")
        return False

    print("🔍 Checking for updates from remote repository...")

    # Fetch latest changes (doesn't modify working directory)
    ret, _, err = run_command("git fetch --quiet")
    if ret != 0:
        print(f"⚠️  Could not fetch updates: {err}")
        print("   (This might be due to no internet connection)")
        return False

    # Get current branch
    ret, branch, _ = run_command("git rev-parse --abbrev-ref HEAD")
    if ret != 0:
        branch = "master"

    # Check if we're behind remote
    ret, behind, _ = run_command(f"git rev-list --count HEAD..origin/{branch}")
    if ret != 0:
        # Remote branch might not exist
        return False

    commits_behind = int(behind) if behind.isdigit() else 0

    if commits_behind == 0:
        print("✅ You're up to date!")
        return False

    # Get list of changes
    ret, changes, _ = run_command(f"git log --oneline HEAD..origin/{branch} --pretty=format:'  - %s'")

    print(f"\n⚡ {commits_behind} update(s) available from remote:")
    print(changes)
    print()

    # Check for local uncommitted changes
    ret, status, _ = run_command("git status --porcelain")
    has_local_changes = bool(status)

    if has_local_changes:
        print("⚠️  You have uncommitted local changes:")
        # Show what's changed
        ret, changed_files, _ = run_command("git status --short")
        print(changed_files[:500])  # Limit output
        print("\nOptions:")
        print("  [1] Stash changes, update, then restore (RECOMMENDED)")
        print("  [2] Skip update (keep current version)")
        print("  [3] Discard local changes and update (DANGEROUS)")

        try:
            choice = input("\nYour choice [1/2/3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nSkipping update.")
            return False

        if choice == '1':
            print("Stashing local changes...")
            run_command("git stash push -m 'auto-update: stashing before pull'")
            perform_update(branch)
            print("Restoring your local changes...")
            ret, _, _ = run_command("git stash pop")
            if ret != 0:
                print("⚠️  Conflicts detected. Please resolve manually with: git status")
            return True
        elif choice == '3':
            if input("Type 'yes' to confirm discarding changes: ").lower() == 'yes':
                run_command("git reset --hard HEAD")
                perform_update(branch)
                return True
            else:
                print("Aborted.")
                return False
        else:
            print("Skipping update.")
            return False
    else:
        # No local changes, safe to update
        response = input("Update now? [Y/n]: ").strip().lower()
        if response in ['', 'y', 'yes']:
            perform_update(branch)
            return True
        else:
            print("Skipping update. You can update later with: git pull")
            return False

def perform_update(branch):
    """Perform the git pull"""
    print(f"Pulling latest changes from origin/{branch}...")
    ret, out, err = run_command(f"git pull origin {branch}")
    if ret == 0:
        print("✅ Update complete!")
        if "Already up to date" not in out:
            print("\nUpdated files:")
            print(out)
    else:
        print(f"❌ Update failed: {err}")
        print("Please update manually with: git pull")

def main():
    """Main entry point"""
    # Only check if stdin is a terminal (not running in background)
    if not sys.stdin.isatty():
        return 0

    # Only check if TI_AUTO_UPDATE is not disabled
    if os.getenv('TI_AUTO_UPDATE') == 'disabled':
        return 0

    try:
        check_for_updates()
    except KeyboardInterrupt:
        print("\nUpdate check cancelled.")
    except Exception as e:
        print(f"Error during update check: {e}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
