# Tests Directory

Security, unit, and integration tests for the Threat Intel Tools toolkit.

## Running Tests

### Security Tests (No Dependencies)

The standalone security tests require only Python 3 (no pytest required):

```bash
# Run security validation tests
python3 tests/test_security_standalone.py

# Should output: "Test Results: 12/12 passed"
```

### With pytest (Optional)

If pytest is installed, you can run the full test suite:

```bash
pip install pytest
python3 -m pytest tests/ -v
```

## Test Modules

### test_security.py

Comprehensive security validation tests using pytest framework:
- Hardcoded API key detection
- Unsafe subprocess usage (shell=True prevention)
- Credential handling and .env management
- File permissions and git-ignore entries
- Input validation for path traversal prevention
- Dependency security

**Note:** Requires pytest. For a standalone version without dependencies, see test_security_standalone.py

### test_security_standalone.py

Standalone security tests that run with Python 3 only (no pytest required):
- Validates no hardcoded API keys exist
- Verifies shell=True is not used in subprocess calls
- Checks .env and credentials are properly git-ignored
- Verifies SECURITY.md documentation exists
- Confirms required .gitignore entries
- Validates config directory structure
- Checks security-related dependencies

## Test Categories

Tests are organized into the following categories:

### Security Tests (test_security.py)
- `TestNoHardcodedApiKeys` - API key management
- `TestNoShellTrue` - Subprocess safety
- `TestCredentialHandling` - Credential security
- `TestSecurityDocumentation` - Documentation completeness
- `TestFilePermissions` - File permission security
- `TestInputValidation` - Input validation
- `TestDependencySecurity` - Dependency tracking
- `TestLoggingAndErrorHandling` - Data leak prevention
- `TestConfigurationSecurity` - Configuration security

## Security Best Practices Validated

The tests validate the following security practices:

1. **No Hardcoded Secrets**
   - API keys loaded from environment variables
   - .env files excluded from git
   - Config templates use ${ENV_VAR} placeholders

2. **Safe Subprocess Usage**
   - No shell=True in subprocess calls
   - All commands passed as argument lists
   - Prevents shell injection vulnerabilities

3. **Proper Credential Handling**
   - .env files in .gitignore
   - config/threat_intel.yml in .gitignore
   - targets.txt marked as sensitive
   - Environment variable support

4. **Documentation**
   - SECURITY.md exists and documents practices
   - API key handling documented
   - Subprocess security documented

5. **File Security**
   - Results directories git-ignored
   - Cache and logs directories excluded
   - Baselines directory excluded

## Continuous Integration

To integrate tests into CI/CD:

```bash
# Run tests and fail on error
python3 tests/test_security_standalone.py || exit 1

# Or with pytest
python3 -m pytest tests/test_security.py -v --tb=short || exit 1
```

## Adding New Tests

To add new security tests:

1. Add test class and methods to `test_security.py` (for pytest)
2. Add corresponding test to `test_security_standalone.py` (for standalone)
3. Follow naming convention: `test_<description>`
4. Document what security practice is being validated
5. Ensure tests are deterministic and don't require external resources

Example:

```python
# In test_security.py
class TestNewSecurity:
    def test_something_secure(self):
        """Verify security practice X is implemented."""
        # Test implementation
        assert True

# In test_security_standalone.py
def run_tests():
    # Add test
    try:
        # Test logic
        results.pass_test("New security check")
    except Exception as e:
        results.fail_test("New security check", str(e))
```

## Troubleshooting

### Test Fails: "Found hardcoded API keys"
- Check `config/threat_intel.yml` uses `${NVD_API_KEY}` format
- Verify no real API keys are in any files
- Use environment variables instead

### Test Fails: "shell=True in subprocess"
- Look in mentioned files for `subprocess.run(cmd, shell=True)`
- Replace with `subprocess.run(cmd_list)` using argument list
- See SECURITY.md for examples

### Test Fails: ".gitignore entries"
- Ensure .gitignore contains required entries
- Check entries are not commented out
- Verify file was saved properly

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)
- [Subprocess Security](https://docs.python.org/3/library/subprocess.html#security-considerations)
