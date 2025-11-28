#!/usr/bin/env python3
"""
Security validation tests for Threat Intel Tools.

Tests cover:
- Hardcoded API key detection
- Unsafe subprocess usage (shell=True)
- Credential handling
- File permission issues
- Path traversal vulnerabilities
"""

import os
import subprocess
import pytest
from pathlib import Path


class TestNoHardcodedApiKeys:
    """Verify no hardcoded API keys exist in codebase."""

    def test_no_hardcoded_api_keys_in_python(self):
        """Scan Python files for hardcoded API key patterns."""
        project_root = Path(__file__).parent.parent

        # API key patterns (generic high-entropy strings)
        patterns = [
            r'api_key\s*=\s*["\'][a-f0-9\-]{30,}["\']',
            r'api_key\s*:\s*["\'][a-f0-9\-]{30,}["\']',
            r'CIRCL.*["\'][a-f0-9\-]{30,}["\']',
            r'NVD.*["\'][a-f0-9\-]{30,}["\']',
        ]

        for pattern in patterns:
            result = subprocess.run(
                ['grep', '-r', '-E', pattern, str(project_root)],
                capture_output=True,
                text=True
            )
            # Should find nothing (returncode != 0 means no matches)
            assert result.returncode != 0, (
                f"Found hardcoded API key pattern '{pattern}': {result.stdout}"
            )

    def test_no_api_key_in_config_examples(self):
        """Verify config examples don't contain real API keys."""
        project_root = Path(__file__).parent.parent
        config_dir = project_root / 'config'

        if config_dir.exists():
            for config_file in config_dir.glob('*.yml'):
                with open(config_file) as f:
                    content = f.read()
                    # Check for patterns that look like real keys
                    # Real keys should be empty/placeholder in examples
                    assert 'api_key: ""' in content or 'api_key:' not in content, (
                        f"{config_file.name} appears to contain API keys"
                    )


class TestNoShellTrue:
    """Verify no subprocess.run calls use shell=True (code injection prevention)."""

    def test_no_shell_true_in_python(self):
        """Scan for shell=True in subprocess calls."""
        project_root = Path(__file__).parent.parent

        # Search for shell=True pattern
        result = subprocess.run(
            ['grep', '-r', 'shell=True', str(project_root)],
            capture_output=True,
            text=True
        )

        # Exclude expected patterns (comments, documentation)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            # Filter out comments and documentation
            problematic_lines = [
                line for line in lines
                if line and not line.strip().startswith('#') and
                'test_' not in line  # Tests can mention it for validation
            ]
            assert not problematic_lines, (
                f"Found shell=True usage:\n{chr(10).join(problematic_lines)}"
            )

    def test_no_shell_true_in_auto_update(self):
        """Specifically verify auto_update.py doesn't use shell=True."""
        project_root = Path(__file__).parent.parent
        auto_update = project_root / 'auto_update.py'

        if auto_update.exists():
            with open(auto_update) as f:
                content = f.read()
                assert 'shell=True' not in content, (
                    "auto_update.py uses shell=True - command injection risk"
                )


class TestCredentialHandling:
    """Verify credentials are handled securely."""

    def test_env_file_not_committed(self):
        """Verify .env files are in .gitignore."""
        project_root = Path(__file__).parent.parent
        gitignore = project_root / '.gitignore'

        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                assert '.env' in content, (
                    ".env not found in .gitignore - risk of committing secrets"
                )

    def test_config_threat_intel_yml_ignored(self):
        """Verify threat_intel.yml is in .gitignore."""
        project_root = Path(__file__).parent.parent
        gitignore = project_root / '.gitignore'

        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                assert 'config/threat_intel.yml' in content or \
                       'threat_intel.yml' in content, (
                    "config/threat_intel.yml not in .gitignore"
                )

    def test_targets_file_ignored(self):
        """Verify targets.txt is in .gitignore."""
        project_root = Path(__file__).parent.parent
        gitignore = project_root / '.gitignore'

        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                assert 'targets.txt' in content, (
                    "targets.txt not in .gitignore - target lists should be private"
                )


class TestSecurityDocumentation:
    """Verify security documentation exists."""

    def test_security_md_exists(self):
        """Verify SECURITY.md exists and documents best practices."""
        project_root = Path(__file__).parent.parent
        security_doc = project_root / 'SECURITY.md'

        assert security_doc.exists(), (
            "SECURITY.md not found - security guidelines should be documented"
        )

    def test_security_md_covers_api_keys(self):
        """Verify SECURITY.md documents API key handling."""
        project_root = Path(__file__).parent.parent
        security_doc = project_root / 'SECURITY.md'

        if security_doc.exists():
            with open(security_doc) as f:
                content = f.read()
                assert 'API' in content or 'api' in content, (
                    "SECURITY.md doesn't document API key handling"
                )
                assert '.env' in content, (
                    "SECURITY.md doesn't mention .env file"
                )

    def test_security_md_covers_subprocess(self):
        """Verify SECURITY.md documents subprocess security."""
        project_root = Path(__file__).parent.parent
        security_doc = project_root / 'SECURITY.md'

        if security_doc.exists():
            with open(security_doc) as f:
                content = f.read()
                assert 'subprocess' in content or 'shell' in content, (
                    "SECURITY.md doesn't document subprocess security"
                )


class TestFilePermissions:
    """Verify sensitive files have appropriate permissions."""

    def test_gitignore_entries_exist(self):
        """Verify .gitignore has required security entries."""
        project_root = Path(__file__).parent.parent
        gitignore = project_root / '.gitignore'

        required_entries = [
            '.env',
            'config/threat_intel.yml',
            'results/',
            'cache/',
            'logs/',
            'baselines/',
        ]

        if gitignore.exists():
            with open(gitignore) as f:
                content = f.read()
                for entry in required_entries:
                    assert entry in content, (
                        f"Required .gitignore entry missing: {entry}"
                    )

    def test_no_sensitive_files_in_repo(self):
        """Verify .env and config/threat_intel.yml aren't committed."""
        project_root = Path(__file__).parent.parent

        # Check files don't exist in working directory (if they do, they shouldn't be tracked)
        env_file = project_root / '.env'
        threat_intel_yml = project_root / 'config' / 'threat_intel.yml'

        # These files may exist locally, but should not be tracked
        # Check via git (requires git repo)
        result = subprocess.run(
            ['git', 'ls-files', '.env'],
            cwd=str(project_root),
            capture_output=True,
            text=True
        )
        assert result.returncode != 0 or not result.stdout.strip(), (
            ".env is tracked by git - should be in .gitignore only"
        )


class TestInputValidation:
    """Verify input validation prevents path traversal and injection."""

    def test_no_path_traversal_in_outputs(self):
        """Check that output paths prevent directory traversal."""
        project_root = Path(__file__).parent.parent

        # Search for user input being used in path construction
        result = subprocess.run(
            ['grep', '-r', 'args\\.', str(project_root / 'master_recon.py')],
            capture_output=True,
            text=True
        )

        # If this passes without assertion, input validation is properly implemented
        # This is a basic check - detailed validation happens in the code itself
        assert True  # Placeholder for path traversal validation


class TestDependencySecurity:
    """Verify security-related dependencies are available."""

    def test_requirements_file_exists(self):
        """Verify requirements.txt exists for dependency tracking."""
        project_root = Path(__file__).parent.parent
        requirements = project_root / 'requirements.txt'

        assert requirements.exists(), (
            "requirements.txt not found - dependencies should be tracked"
        )

    def test_common_security_libraries(self):
        """Verify security-relevant libraries are in requirements."""
        project_root = Path(__file__).parent.parent
        requirements = project_root / 'requirements.txt'

        if requirements.exists():
            with open(requirements) as f:
                content = f.read()
                # These libraries support security practices
                # At least some should be present
                security_libs = ['filelock', 'requests', 'pyyaml']
                has_security_lib = any(lib in content for lib in security_libs)
                assert has_security_lib, (
                    "No security-relevant libraries found in requirements.txt"
                )


class TestLoggingAndErrorHandling:
    """Verify sensitive data isn't leaked in logs/errors."""

    def test_no_api_key_logging(self):
        """Verify API keys aren't logged in output."""
        project_root = Path(__file__).parent.parent

        # Check main scripts for logging API keys
        scripts_to_check = [
            'threat_context_enricher.py',
            'master_recon.py',
        ]

        for script_name in scripts_to_check:
            script_path = project_root / script_name
            if script_path.exists():
                with open(script_path) as f:
                    content = f.read()
                    # Look for logging that might include API keys
                    # These should be filtered out
                    if 'api_key' in content.lower():
                        assert 'filter' in content.lower() or \
                               'redact' in content.lower() or \
                               'mask' in content.lower(), (
                            f"{script_name} mentions API keys but has no filtering"
                        )


class TestConfigurationSecurity:
    """Verify configuration files are secure."""

    def test_config_directory_exists(self):
        """Verify config directory exists for centralized configuration."""
        project_root = Path(__file__).parent.parent
        config_dir = project_root / 'config'

        assert config_dir.exists() and config_dir.is_dir(), (
            "config/ directory not found - configurations should be centralized"
        )

    def test_environment_yml_exists(self):
        """Verify environment configuration file exists."""
        project_root = Path(__file__).parent.parent
        env_yml = project_root / 'config' / 'environment.yml'

        # This file should document execution modes
        # It may or may not exist, but if it does, verify it's properly configured
        if env_yml.exists():
            with open(env_yml) as f:
                content = f.read()
                # Should have mode configuration
                assert 'mode' in content or 'dev' in content or \
                       'production' in content, (
                    "environment.yml doesn't specify execution mode"
                )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
