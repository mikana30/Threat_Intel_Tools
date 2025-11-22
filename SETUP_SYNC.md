# Setup Guide: Keeping Environments in Sync

This guide explains how to keep your threat intel toolkit synchronized across multiple machines (main workstation + VM).

## Initial Setup (One-Time)

### 1. Create Git Repository

Choose one of these options:

**Option A: GitHub (Recommended for Internet Access)**
```bash
# On your main machine
cd "/path/to/Threat Intel Tools and Work Flow"

# Create .gitignore
cat > .gitignore <<'EOF'
# Results and outputs
results/
*.log
trace.log*
ornl_*.log
fermi_*.log

# Cache and state files
cache/
baselines/
*.pyc
__pycache__/
venv/
.venv/

# Sensitive data (never commit these!)
targets.txt
targets_*.txt
keys.json

# Binary/large files
*.tar.gz
chromedriver_*
go*.linux-amd64.tar.gz
image.png

# IDE files
.vscode/
.idea/
EOF

# Initialize and add remote
git add .
git commit -m "Initial commit: threat intel toolkit"
git branch -M main
git remote add origin https://github.com/yourusername/threat-intel-toolkit.git
git push -u origin main
```

**Option B: Self-Hosted Git (for Air-Gapped/Isolated)**
```bash
# On a shared server both machines can reach
mkdir -p /shared/git/threat-intel.git
cd /shared/git/threat-intel.git
git init --bare

# On your main machine
git remote add origin user@server:/shared/git/threat-intel.git
git push -u origin main
```

### 2. Clone on Second Machine/VM

```bash
# On VM or second machine
cd ~/Desktop/threat_intel
git clone https://github.com/yourusername/threat-intel-toolkit.git "Threat Intel Tools and Work Flow"
cd "Threat Intel Tools and Work Flow"

# Install dependencies
pip3 install -r requirements.txt  # If you create one
```

### 3. Configure Auto-Update (Built-In)

The auto-update checker is **enabled by default**. It will:
- Check for updates before each workflow run
- Prompt you to update if changes are available
- Handle local changes safely (stash/restore)

**To disable auto-updates:**
```bash
export TI_AUTO_UPDATE=disabled
```

## Daily Workflow

### On Machine 1 (Where You Make Changes)

After making changes to scripts or configs:

```bash
# 1. Check what changed
git status

# 2. Add specific files
git add prepare_priority_screenshots.py threat_context_enricher.py
git add Reporting_Toolkit/generate_report.py

# Or add all changes
git add -u

# 3. Commit with descriptive message
git commit -m "fix: filter cloud storage errors from report"

# 4. Push to remote
git push
```

**Commit Message Format (recommended):**
- `fix:` - Bug fixes
- `feat:` - New features
- `chore:` - Maintenance/cleanup
- `docs:` - Documentation updates

Examples:
```bash
git commit -m "fix: CSV field size limit for large directory listings"
git commit -m "feat: add smart screenshot filtering"
git commit -m "chore: update ORNL baseline"
```

### On Machine 2 / VM (Pulling Updates)

**Automatic (Recommended):**
Just run your workflow - it will prompt for updates:
```bash
python3 master_recon.py --organization "TestOrg"
```

Output will show:
```
🔍 Checking for updates from remote repository...
⚡ 3 update(s) available from remote:
  - fix: filter cloud storage errors from report
  - fix: CSV field size limit
  - feat: add smart screenshot filtering

Update now? [Y/n]:
```

**Manual:**
```bash
git pull
```

## Handling Conflicts

If you've made changes on both machines, you might get conflicts:

```bash
# Pull with rebase (cleaner history)
git pull --rebase

# If conflicts occur
git status  # Shows conflicted files

# Edit files to resolve conflicts
# Look for <<<<<<< HEAD markers

# After resolving
git add <resolved-files>
git rebase --continue

# Or abort and try manual merge
git rebase --abort
git pull  # Creates merge commit
```

## Quick Commands Reference

```bash
# Check status
git status

# See what changed
git diff

# View commit history
git log --oneline -10

# See remote updates without pulling
git fetch
git log HEAD..origin/main --oneline

# Undo last commit (keep changes)
git reset --soft HEAD~1

# Discard all local changes (CAREFUL!)
git reset --hard HEAD

# Stash changes temporarily
git stash
git pull
git stash pop
```

## Best Practices

1. **Commit frequently** - Small, focused commits are easier to track
2. **Pull before starting work** - Avoid conflicts
3. **Don't commit sensitive data** - Use .gitignore
4. **Test before pushing** - Ensure scripts work
5. **Use descriptive messages** - Future you will thank you

## Excluding Results/Logs

The `.gitignore` file ensures these never get committed:
- `results/` - Scan outputs (can be huge)
- `*.log` - Log files
- `cache/` - CVE cache databases
- `baselines/` - Baseline comparisons
- `targets.txt` - Target lists (may be sensitive)

## Troubleshooting

### "Not a git repository"
```bash
git init
git remote add origin <your-repo-url>
```

### "No git remote configured"
```bash
git remote add origin <your-repo-url>
git push -u origin main
```

### "Permission denied (publickey)"
```bash
# Set up SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"
cat ~/.ssh/id_ed25519.pub  # Add to GitHub/GitLab
```

### Auto-update not working
```bash
# Check if disabled
echo $TI_AUTO_UPDATE

# Manually check
python3 auto_update.py

# Check git fetch
git fetch --dry-run
```

## Advanced: Pre-Commit Hooks

Automatically check code before committing:

```bash
# Create pre-commit hook
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/bash
# Check for syntax errors in Python files
for file in $(git diff --cached --name-only | grep '\.py$'); do
    python3 -m py_compile "$file"
    if [ $? -ne 0 ]; then
        echo "Syntax error in $file"
        exit 1
    fi
done
EOF

chmod +x .git/hooks/pre-commit
```

## Security Notes

**Never commit:**
- API keys (use `keys.json.example` as template)
- Target lists with sensitive org names
- Results with PII/sensitive data
- Credentials or passwords

**Safe to commit:**
- Python scripts
- Configuration templates
- Documentation
- Workflow specifications
- Example configs

---

**Questions?** See CLAUDE.md for architecture details or CONTEXT.md for recent changes.
