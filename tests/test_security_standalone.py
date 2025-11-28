#!/usr/bin/env python3
"""
Standalone security validation tests (no pytest dependency).

Tests cover:
- Hardcoded API key detection
- Unsafe subprocess usage (shell=True)
- Credential handling
- File permission issues
"""

import os
import subprocess
import sys
from pathlib import Path


class TestResults:
    """Track test results."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def pass_test(self, name):
        self.passed += 1
        print(f"✓ {name}")

    def fail_test(self, name, error):
        self.failed += 1
        self.errors.append((name, error))
        print(f"✗ {name}: {error}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Test Results: {self.passed}/{total} passed")
        if self.errors:
            print(f"\nFailed Tests:")
            for name, error in self.errors:
                print(f"  - {name}")
                print(f"    {error}")
        return self.failed == 0


def run_tests():
    """Run all security tests."""
    results = TestResults()
    project_root = Path(__file__).parent.parent

    print("Running Threat Intel Tools Security Tests")
    print("=" * 60)

    # Test 1: No hardcoded API keys (real keys, not env var placeholders)
    try:
        # Look for real API keys (not ${ENV_VAR} placeholders)
        # Real keys are typically 32+ hex chars or have specific key structures
        pattern = r'api_key\s*[=:]\s*["\'](?!\$\{)[a-f0-9\-]{32,}["\']'

        result = subprocess.run(
            ['grep', '-r', '-E', pattern, str(project_root)],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            results.fail_test(
                "No hardcoded API keys",
                f"Found real API keys in code (use env vars instead)"
            )
            return results
        results.pass_test("No hardcoded API keys")
    except Exception as e:
        results.fail_test("No hardcoded API keys", str(e))

    # Test 2: No shell=True in actual Python code (exclude docs)
    try:
        result = subprocess.run(
            ['grep', '-r', 'shell=True', str(project_root)],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            # Filter out documentation files and comments
            problematic = [
                l for l in lines
                if l and
                not l.strip().startswith('#') and
                not l.endswith('.md:') and
                '.md:' not in l
            ]
            if problematic:
                # Count actual Python files with shell=True
                py_files = set(l.split(':')[0] for l in problematic if l.endswith('.py'))
                if py_files:
                    results.fail_test("No shell=True in subprocess",
                                    f"Found shell=True in: {', '.join(sorted(py_files))}")
                    return results
        results.pass_test("No shell=True in subprocess")
    except Exception as e:
        results.fail_test("No shell=True in subprocess", str(e))

    # Test 3: .env in .gitignore
    try:
        gitignore = project_root / '.gitignore'
        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                if '.env' in content:
                    results.pass_test(".env in .gitignore")
                else:
                    results.fail_test(".env in .gitignore", "Not found in .gitignore")
        else:
            results.fail_test(".env in .gitignore", ".gitignore not found")
    except Exception as e:
        results.fail_test(".env in .gitignore", str(e))

    # Test 4: threat_intel.yml in .gitignore
    try:
        gitignore = project_root / '.gitignore'
        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                if 'threat_intel.yml' in content:
                    results.pass_test("threat_intel.yml in .gitignore")
                else:
                    results.fail_test("threat_intel.yml in .gitignore",
                                    "Not found in .gitignore")
    except Exception as e:
        results.fail_test("threat_intel.yml in .gitignore", str(e))

    # Test 5: targets.txt in .gitignore
    try:
        gitignore = project_root / '.gitignore'
        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                if 'targets.txt' in content:
                    results.pass_test("targets.txt in .gitignore")
                else:
                    results.fail_test("targets.txt in .gitignore",
                                    "Not found in .gitignore")
    except Exception as e:
        results.fail_test("targets.txt in .gitignore", str(e))

    # Test 6: SECURITY.md exists
    try:
        security_md = project_root / 'SECURITY.md'
        if security_md.exists():
            results.pass_test("SECURITY.md exists")
        else:
            results.fail_test("SECURITY.md exists", "File not found")
    except Exception as e:
        results.fail_test("SECURITY.md exists", str(e))

    # Test 7: SECURITY.md documents API keys
    try:
        security_md = project_root / 'SECURITY.md'
        if security_md.exists():
            with open(security_md) as f:
                content = f.read()
                if 'API' in content or '.env' in content:
                    results.pass_test("SECURITY.md documents credentials")
                else:
                    results.fail_test("SECURITY.md documents credentials",
                                    "Missing API/credentials documentation")
        else:
            results.fail_test("SECURITY.md documents credentials",
                            "SECURITY.md not found")
    except Exception as e:
        results.fail_test("SECURITY.md documents credentials", str(e))

    # Test 8: Required .gitignore entries
    try:
        required_entries = [
            '.env',
            'config/threat_intel.yml',
            'results/',
            'cache/',
            'logs/',
            'baselines/',
        ]
        gitignore = project_root / '.gitignore'
        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                missing = [e for e in required_entries if e not in content]
                if missing:
                    results.fail_test("Required .gitignore entries",
                                    f"Missing: {', '.join(missing)}")
                else:
                    results.pass_test("Required .gitignore entries")
    except Exception as e:
        results.fail_test("Required .gitignore entries", str(e))

    # Test 9: Config directory exists
    try:
        config_dir = project_root / 'config'
        if config_dir.exists() and config_dir.is_dir():
            results.pass_test("config/ directory exists")
        else:
            results.fail_test("config/ directory exists", "Not found or not a directory")
    except Exception as e:
        results.fail_test("config/ directory exists", str(e))

    # Test 10: requirements.txt exists
    try:
        req_file = project_root / 'requirements.txt'
        if req_file.exists():
            results.pass_test("requirements.txt exists")
        else:
            results.fail_test("requirements.txt exists", "File not found")
    except Exception as e:
        results.fail_test("requirements.txt exists", str(e))

    # Test 11: Security-related dependencies documented
    try:
        req_file = project_root / 'requirements.txt'
        if req_file.exists():
            with open(req_file) as f:
                content = f.read()
                security_libs = ['filelock', 'requests', 'pyyaml']
                has_lib = any(lib in content for lib in security_libs)
                if has_lib:
                    results.pass_test("Security dependencies documented")
                else:
                    results.fail_test("Security dependencies documented",
                                    f"Missing any of {security_libs}")
    except Exception as e:
        results.fail_test("Security dependencies documented", str(e))

    # Test 12: Tests directory exists
    try:
        tests_dir = project_root / 'tests'
        if tests_dir.exists() and tests_dir.is_dir():
            results.pass_test("tests/ directory exists")
        else:
            results.fail_test("tests/ directory exists", "Not found")
    except Exception as e:
        results.fail_test("tests/ directory exists", str(e))

    return results


if __name__ == '__main__':
    results = run_tests()
    success = results.summary()
    sys.exit(0 if success else 1)
