# Security Best Practices

## API Keys & Credentials

1. **Never commit API keys to git** - Use environment variables or .env files
2. **Use .env file** - Copy from `.env.example` and populate with your credentials
3. **Environment variables** - Set via system or shell configuration, not in code
4. **Rotate keys every 90 days** - Maintain a credential rotation schedule
5. **Review git history** - Use `git log -p -- <file>` to check for accidental leaks

### Credential Management
```bash
# Create .env from template
cp .env.example .env

# Load environment before running
source .env
python3 master_recon.py --organization "TestOrg"

# Never commit .env or config/threat_intel.yml
git check-ignore .env config/threat_intel.yml
```

## Current Security Measures

### Code-Level Protections
- **Atomic file writes** - Use atomic operations with `os.replace()` to prevent race conditions during file updates
- **File locking** - Prevent concurrent processes from corrupting shared state files (WHOIS, VNC scan state)
- **Input validation** - Validate all user inputs to prevent path traversal attacks
- **No shell=True in subprocess** - All subprocess calls use argument lists, not shell interpretation
- **Sanitized logging** - Sensitive data is filtered from log output

### Process Security
- **Isolated execution** - Each scan stage runs in separate processes with proper isolation
- **Resource limits** - ThreadPoolExecutor and connection pools prevent resource exhaustion
- **Timeout enforcement** - All network operations have configurable timeouts
- **Error handling** - Comprehensive error handling prevents information leakage in error messages

### Data Security
- **Results isolation** - Output directories are created with restrictive permissions (0o755)
- **Cache cleanup** - Temporary files and caches are removed after use
- **No hardcoded secrets** - All sensitive configuration uses environment variables
- **WHOIS rate limiting** - Prevents detection as aggressive scanner

## Security Configuration

### Environment Variables
Configure these securely in `.env`:
```
# API Keys
NVD_API_KEY=your_key_here
CIRCL_CERT_API_KEY=your_key_here

# Scanner Settings
TI_MODE=production
TI_AUTO_UPDATE=enabled

# Rate Limits
WHOIS_BATCH_SIZE=100
WHOIS_RATE_LIMIT=10
```

### File Permissions
Ensure sensitive files have restricted permissions:
```bash
chmod 600 .env                    # Owner read/write only
chmod 600 config/threat_intel.yml # Owner read/write only
chmod 755 results/                # Results accessible to group
```

## Vulnerability Scanning

The toolkit includes security scanning capabilities:
- **S3_Bucket_Check.py** - Detects misconfigured AWS S3 buckets
- **Cloud_Misconfig.py** - Identifies cloud storage exposures
- **Git_Leak.py** - Scans for exposed .git repositories
- **Email_Security_Audit.py** - Validates SPF/DMARC/MX records

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** create a public issue on GitHub
2. **Email** the project maintainers with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if applicable)
3. **Allow 90 days** for fix and release before disclosure
4. **Coordinate** with maintainers on responsible disclosure timeline

## Security Audit Checklist

Before running in production:
- [ ] Review `.env.example` - all required variables documented
- [ ] Verify `.env` is git-ignored in `.gitignore`
- [ ] Check file permissions on `.env` and config files (chmod 600)
- [ ] Run security tests: `python3 -m pytest tests/test_security.py`
- [ ] Review `threat_context_enricher.py` - no API keys logged
- [ ] Verify `config/threat_intel.yml` is not committed
- [ ] Check `results/` directory has appropriate read permissions
- [ ] Audit recent git history for accidental commits: `git log --all --full-history -- .env`

## Common Security Issues & Fixes

### Hardcoded API Keys
**Problem:** API keys in source code
**Solution:** Move to `.env` file and load with `os.environ.get()`

### Overly Permissive File Permissions
**Problem:** Output files readable by all users
**Solution:** Create with mode `0o600` and adjust as needed

### Shell Injection
**Problem:** `subprocess.run(cmd, shell=True)`
**Solution:** Use `subprocess.run(cmd_list)` with argument list

### Unencrypted State Files
**Problem:** Plain-text WHOIS/VNC state files contain sensitive data
**Solution:** Keep state files in results/ (git-ignored) and use .env for API keys

## Regular Maintenance

### Weekly
- Review error logs for security-related messages
- Check for failed authentication attempts
- Monitor resource usage for anomalies

### Monthly
- Rotate API keys
- Review git log for accidental commits
- Update Python dependencies: `pip install --upgrade -r requirements.txt`

### Quarterly
- Full security audit checklist
- Update scanning rules and patterns
- Review threat intelligence sources

## Dependencies Security

Keep Python packages updated:
```bash
pip install --upgrade pip
pip install --upgrade -r requirements.txt
pip check  # Detect known vulnerabilities
```

Monitor for CVEs in dependencies:
- Watch GitHub security advisories
- Use `safety check` for vulnerability scanning
- Review `requirements.txt` regularly

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)
- [Subprocess Security](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Git Security](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
