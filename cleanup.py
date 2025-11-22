#!/usr/bin/env python3

import os
import shutil
import glob

def main():
    """
    Finds and deletes all generated artifacts from the workflow to ensure a clean slate,
    while preserving essential input files like 'requirements.txt' and all 'targets*.txt' files.
    """
    project_root = os.getcwd()
    print(f"[*] Starting cleanup in: {project_root}\n")

    # --- List of essential files to PRESERVE by exact name ---
    files_to_keep_exact = [
        'requirements.txt'
    ]

    # --- 1. Directories to remove entirely ---
    dirs_to_remove = [
        'outputs',
        'logs'
    ]
    for dir_name in dirs_to_remove:
        path = os.path.join(project_root, dir_name)
        if os.path.isdir(path):
            try:
                print(f"[-] Deleting directory: {dir_name}/")
                shutil.rmtree(path)
            except Exception as e:
                print(f"[!] Error deleting {path}: {e}")

    # --- 2. Top-level files to remove by pattern (with safety checks) ---
    file_patterns_to_remove = [
        '*.txt',
        '*.csv',
        '*.xlsx'
    ]
    print("\n[*] Checking for top-level artifact files...")
    for pattern in file_patterns_to_remove:
        for file_path in glob.glob(os.path.join(project_root, pattern)):
            file_name = os.path.basename(file_path)
            
            # SAFETY CHECK 1: Skip if the file is in the exact-match keep list.
            if file_name in files_to_keep_exact:
                print(f"[*] Skipping preserved file: {file_name}")
                continue

            # SAFETY CHECK 2: Skip any file that starts with 'targets' and ends with '.txt'
            if file_name.startswith('targets') and file_name.endswith('.txt'):
                print(f"[*] Skipping preserved targets file: {file_name}")
                continue

            try:
                print(f"[-] Deleting file: {file_name}")
                os.remove(file_path)
            except Exception as e:
                print(f"[!] Error deleting {file_path}: {e}")

    # --- 3. Intelligently find and remove per-domain directories ---
    print("\n[*] Searching for per-domain artifact directories...")
    recon_files = glob.glob(os.path.join(project_root, '*/*_recon.csv'))
    
    domain_dirs_to_remove = set()
    for recon_file in recon_files:
        domain_dirs_to_remove.add(os.path.dirname(recon_file))

    if not domain_dirs_to_remove:
        print("[-] No per-domain directories found.")
    else:
        for dir_path in domain_dirs_to_remove:
            dir_name = os.path.basename(dir_path)
            if os.path.isdir(dir_path):
                try:
                    print(f"[-] Deleting per-domain directory: {dir_name}/")
                    shutil.rmtree(dir_path)
                except Exception as e:
                    print(f"[!] Error deleting {dir_path}: {e}")

    print("\n[+] Cleanup complete. The project directory is now clean.")

if __name__ == "__main__":
    main()
