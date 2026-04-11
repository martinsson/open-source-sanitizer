# Complementary Scanning Tools for Open Source Migration

This document describes additional scanning tools and procedures that complement `oss-sanitizer` when preparing a codebase for open-source release. It covers information leakage detection, git history scanning, and configuration auditing.

---

## Section 1: Information Leakage Detection (Current Code)

Detects internal APIs, service names, domain references, and other infrastructure patterns beyond basic secrets.

| **Tool** | **What it detects** | **Notes** |
|----------|-----------------|---------|
| **[Semgrep](https://semgrep.dev/)** | Custom pattern matching (internal APIs, domain names, service names, etc.) | Write custom rules for your internal patterns; scans current code only |
| **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** | Secrets + entropy-based detection of tokens/keys | Can be extended with regex patterns for internal hostnames |
| **[detect-secrets](https://github.com/Yelp/detect-secrets)** | Broader secret patterns than basic scanners | Good baseline for credential-like patterns |

**Best approach**: Use **Semgrep with custom rules** to catch your specific internal patterns (e.g., regex for `internal-api.company.com`, `service-.*\.internal`, etc.)

### Example Semgrep Rules

```yaml
# Custom rules file: semgrep-internal-patterns.yml
rules:
  - id: internal-domain-reference
    pattern-either:
      - pattern: |
          $X = "*.internal.example.com"
      - pattern: |
          url = $DOMAIN
          metavars:
            $DOMAIN:
              regex: '.*\.internal\.example\.com.*'
    message: Internal domain reference detected
    severity: WARNING

  - id: internal-service-name
    pattern-regex: |
      (srv[-_][a-zA-Z0-9][-a-zA-Z0-9_.]*)|(service-prod)|(api-internal)
    message: Possible internal service name
    severity: WARNING
```

Run:
```bash
semgrep scan --config=semgrep-internal-patterns.yml .
```

---

## Section 2: Git History Scanning (ALL Blobs)

Automatically scans all commits and all blobs—no manual loops needed.

| **Tool** | **Blob coverage** | **Notes** |
|----------|-----------------|---------|
| **[gitleaks](https://github.com/gitleaks/gitleaks)** | ✅ Scans all commits by default | `gitleaks detect --source git --verbose` scans entire repo history |
| **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** | ✅ Scans all commits by default | `trufflehog git file://path/to/repo` scans full history |
| **[git-filter-repo](https://github.com/newren/git-filter-repo)** | ✅ Can be scripted to inspect/redact all blobs | Use `--blob-callback` to apply custom logic to every blob; rewrite history in place |

### Usage

```bash
# Scan full git history for secrets (all blobs)
gitleaks detect --source git --verbose

# Alternative: TruffleHog
trufflehog git file://path/to/repo

# Redact sensitive patterns from all historical blobs
git-filter-repo --blob-callback 'python3 redact.py'
```

### Example Redaction Script

```python
# redact.py
import sys
import re

data = sys.stdin.buffer.read()

# Redact internal URLs
data = re.sub(rb'https?://[a-z0-9.-]*\.internal\.example\.com', b'https://redacted.internal', data)

# Redact service names
data = re.sub(rb'srv-prod-\d+', b'srv-redacted', data)

sys.stdout.buffer.write(data)
```

---

## Section 4: Configuration & Environment Concerns

Detects hardcoded paths, environment-specific settings, and configuration misconfigurations.

| **Tool** | **What it catches** | **Scope** |
|----------|-----------------|---------|
| **[Semgrep](https://semgrep.dev/)** (custom rules) | Hardcoded URLs, paths, environment variables | Current code + patterns you define |
| **[checkov](https://www.checkov.io/)** | Misconfigurations in IaC, CI/CD pipelines, build scripts | YAML/JSON configs, GitHub Actions, Terraform, etc. |
| **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** + entropy detection | Hardcoded API keys, tokens in config files | All commits if run on git history |

### Usage

```bash
# Scan configs for hardcoded environment-specific settings
checkov -d . --framework all

# Scan for misconfigurations in CI/CD pipelines
checkov -d .github/workflows --framework github_actions

# Scan Terraform or CloudFormation configs
checkov -d terraform/ --framework terraform
```

---

## Suggested Unified Workflow

Run these complementary tools in sequence to thoroughly prepare your codebase:

```bash
# 1. Scan git history for secrets/tokens (all blobs automatically)
gitleaks detect --source git --verbose

# 2. Scan current code for custom patterns (internal APIs, services, etc.)
semgrep scan --config=semgrep-internal-patterns.yml .

# 3. Scan configs for hardcoded environment-specific settings
checkov -d . --framework all

# 4. Run oss-sanitizer (the primary scanner for your governance framework)
oss-sanitizer . --history

# 5. (Optional) Redact historical blobs if needed
git-filter-repo --blob-callback 'python3 redact.py'
```

---

## CI/CD Integration Example

```yaml
# .github/workflows/oss-compliance.yml
name: OSS Compliance Scan

on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for scanning
      
      - name: Install gitleaks
        run: curl https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh
      
      - name: Scan git history
        run: ./gitleaks detect --source git --verbose
      
      - name: Install Semgrep
        run: pip install semgrep
      
      - name: Scan with Semgrep
        run: semgrep scan --config=semgrep-internal-patterns.yml .
      
      - name: Install Checkov
        run: pip install checkov
      
      - name: Scan configs
        run: checkov -d . --framework all
      
      - name: Run oss-sanitizer
        run: pip install oss-sanitizer && oss-sanitizer . --history -o compliance-report.md
      
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance-report.md
```

---

## Notes

- **Sections 1–2 & 4**: These complement `oss-sanitizer`, which focuses on organizational governance patterns (internal domains, sensitive algorithms, etc.).
- **Section 3** (third-party IP/proprietary code): Requires manual code review—no automated tool can reliably detect this.
- **Git history scanning**: Both `gitleaks` and `TruffleHog` are designed to automatically scan all blobs; no manual blob iteration needed.
- **Custom rules**: Semgrep rules can be tailored to your organization's specific internal patterns and architecture.
