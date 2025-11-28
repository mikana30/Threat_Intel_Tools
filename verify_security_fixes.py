#!/usr/bin/env python3
"""
Verification script for Phase 0 security fixes
"""
import os
import sys
from pathlib import Path

def check_file_exists(path, description):
    """Check if a file exists"""
    if Path(path).exists():
        print(f"✓ {description}: {path}")
        return True
    else:
        print(f"✗ {description}: {path} NOT FOUND")
        return False

def check_import(module_path, symbol, description):
    """Check if a module can be imported"""
    try:
        # Add current directory to path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Import the module
        module = __import__(module_path, fromlist=[symbol])
        if hasattr(module, symbol):
            print(f"✓ {description}: {module_path}.{symbol}")
            return True
        else:
            print(f"✗ {description}: {module_path}.{symbol} NOT FOUND")
            return False
    except Exception as e:
        print(f"✗ {description}: {module_path}.{symbol} - {str(e)}")
        return False

def main():
    print("=" * 70)
    print("CRITICAL SECURITY FIXES - PHASE 0 VERIFICATION")
    print("=" * 70)
    print()
    
    all_passed = True
    
    # Task 1: Secure API Key
    print("Task 1: Secure API Key")
    print("-" * 70)
    all_passed &= check_file_exists("config/threat_intel.yml.example", "Config template")
    all_passed &= check_file_exists(".env.example", "Environment template")
    all_passed &= check_file_exists("SECURITY_NOTICE_API_KEY_ROTATION.txt", "Security notice")
    
    # Check if threat_context_enricher.py has the changes
    try:
        with open("threat_context_enricher.py", "r") as f:
            content = f.read()
            if "os.getenv('NVD_API_KEY'" in content:
                print("✓ threat_context_enricher.py: Environment variable loading")
            else:
                print("✗ threat_context_enricher.py: Missing environment variable loading")
                all_passed = False
    except Exception as e:
        print(f"✗ threat_context_enricher.py: {str(e)}")
        all_passed = False
    
    print()
    
    # Task 2: Command Injection Fixes
    print("Task 2: Command Injection Fixes")
    print("-" * 70)
    try:
        with open("auto_update.py", "r") as f:
            content = f.read()
            if "shell=True" in content:
                print("✗ auto_update.py: Still contains shell=True")
                all_passed = False
            else:
                print("✓ auto_update.py: No shell=True found")
    except Exception as e:
        print(f"✗ auto_update.py: {str(e)}")
        all_passed = False
    
    print()
    
    # Task 3: Atomic State Writes
    print("Task 3: Atomic State Writes")
    print("-" * 70)
    all_passed &= check_file_exists("utils/atomic_write.py", "Atomic write utility")
    all_passed &= check_import("utils.atomic_write", "atomic_write_json", "atomic_write_json function")
    all_passed &= check_import("utils.atomic_write", "atomic_write_text", "atomic_write_text function")
    
    # Check if files use atomic writes
    for filename in ["vnc_scan.py", "distributed_whois.py", "VNC_Checker.py"]:
        try:
            with open(filename, "r") as f:
                content = f.read()
                if "atomic_write_json" in content:
                    print(f"✓ {filename}: Uses atomic_write_json")
                else:
                    print(f"✗ {filename}: Does not use atomic_write_json")
                    all_passed = False
        except Exception as e:
            print(f"✗ {filename}: {str(e)}")
            all_passed = False
    
    print()
    
    # Task 4: File Locking
    print("Task 4: File Locking")
    print("-" * 70)
    all_passed &= check_file_exists("utils/file_lock.py", "File lock utility")
    all_passed &= check_import("utils.file_lock", "locked_file", "locked_file function")
    all_passed &= check_import("utils.file_lock", "locked_file_read", "locked_file_read function")
    
    # Check if VNC_Checker.py uses file locking
    try:
        with open("VNC_Checker.py", "r") as f:
            content = f.read()
            if "locked_file" in content:
                print("✓ VNC_Checker.py: Uses locked_file")
            else:
                print("✗ VNC_Checker.py: Does not use locked_file")
                all_passed = False
    except Exception as e:
        print(f"✗ VNC_Checker.py: {str(e)}")
        all_passed = False
    
    print()
    print("=" * 70)
    if all_passed:
        print("✓ ALL SECURITY FIXES VERIFIED SUCCESSFULLY")
        print("=" * 70)
        return 0
    else:
        print("✗ SOME SECURITY FIXES FAILED VERIFICATION")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(main())
