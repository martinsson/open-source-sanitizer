# Plan: Hostname False Positive Reduction

## Problem

The hostname scanner produces massive false positives in real-world Maven projects. From a scan of `urbafc-commun`:

| False positive | Why it matched | Category |
|----------------|----------------|----------|
| `ci-dessous` | `ci-*` prefix | French text |
| `ci-base-jobs.yml` | `ci-*` prefix | CI filename |
| `mapstruct-test` | `*-test` suffix | Maven module name |
| `api-cas-general.png` | `api-*` prefix | Image filename |
| `api-rejeu.png` | `api-*` prefix | Image filename |
| `jenkins-env.png` | `jenkins-*` prefix | Image filename |
| `jenkins-release.png` | `jenkins-*` prefix | Image filename |
| `git-release` | `git-*` prefix | Asciidoc anchor |
| `process-test-classes` | `*-test*` suffix | Maven lifecycle phase |
| `test-jar` | `test-*` prefix | Maven artifact type |
| `integration-test` | `*-test` suffix | Maven lifecycle phase |
| `app-utils.version` | `app-*` prefix | Maven property name |
| `gina-dev` | `*-dev` suffix | Keystore filename |

**Root cause:** The hostname prefix/suffix lists are too broad. Generic development terms (`api`, `app`, `ci`, `git`, `jenkins`, `test`) appear constantly in source code contexts that have nothing to do with hostnames.

---

## Strategy: Context-Aware Filtering

Instead of tightening the regex (which risks missing real hostnames), add **post-match filters** that discard matches based on surrounding context.

---

## Step 1: Structural filters (high impact, no false negatives)

Discard hostname matches that appear in contexts where hostnames are structurally impossible:

### 1a. File extension filter
If the matched text ends with a known file extension, it's a filename, not a hostname.
```
Reject if match ends with: .png, .jpg, .gif, .svg, .yml, .yaml, .xml, .json, .properties, .java, .py, .js, .ts, .md, .adoc, .txt, .html, .css, .sh, .bat, .jar, .war, .pem, .jks
```
Fixes: `api-cas-general.png`, `jenkins-env.png`, `ci-base-jobs.yml`

### 1b. Maven lifecycle / artifact type exclusion list
Exact-match exclusion for known Maven terms:
```
process-test-classes, test-jar, integration-test, maven-compiler-plugin,
maven-surefire-plugin, maven-failsafe-plugin, maven-deploy-plugin,
maven-release-plugin, maven-jar-plugin, maven-war-plugin,
spring-boot-starter-*, test-compile, pre-integration-test,
post-integration-test, verify, process-resources, process-classes
```

### 1c. Property/variable name filter
If the match is followed by `=`, `.version`, `.groupId`, `.artifactId`, or similar Maven property suffixes, discard it.
```
Reject if followed by: .version, .groupId, .artifactId, .scope, .type, .classifier
```
Fixes: `app-utils.version`

### 1d. Markup/document anchor filter
If the match appears in a markup anchor context (`[[...]]`, `<<...>>`, `#...`, `id="`), discard it.
Fixes: `git-release` in asciidoc

---

## Step 2: Tighten the prefix list (medium impact)

Split the current broad prefix list into two tiers:

**Tier 1 — Always a hostname indicator** (keep as-is):
```
srv, server, db, ldap, ad, dc, dns, mail, smtp, imap, ftp, nfs, nas, san, vpn, gw, fw, lb, mgmt, mon, bkp
```

**Tier 2 — Only a hostname indicator with additional evidence** (require `.` or at least 2 segments):
```
app, web, api, proxy, ci, cd, git, svn, jenkins, nexus, sonar, jira, confluence, log
```

For Tier 2 prefixes, require the match to contain a dot (suggesting a FQDN) OR be followed by a digit (e.g., `api-01`, `web-03`):
```regex
\b(?:app|web|api|...)[-_][a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*\b
```

This keeps `api-prod.internal` and `jenkins-01.ge.ch` but drops `api-cas-general` and `jenkins-release`.

---

## Step 3: Tighten the environment suffix list

The current pattern `\b[a-zA-Z]+-(?:prod|dev|test|int|...)\b` is too greedy.

**Remove from suffix list:**
- `test` — ubiquitous in code (`mapstruct-test`, `unit-test`, `integration-test`)
- `int` — French abbreviation, Maven convention, Java type

**Keep with stricter context:**
- `dev` — only flag if preceded by a hostname-like prefix or followed by a digit/dot
- `prod`, `staging`, `preprod`, `recette`, `uat`, `qual` — safe to keep (rarely used outside infra)

Revised suffix pattern:
```regex
\b[a-zA-Z]{2,}[-_](?:prod|staging|stage|stg|preprod|recette|rct|qual|qualif|uat)\b
```

And for `dev`/`test` specifically:
```regex
\b(?:srv|server|db|app|web|api|proxy|ldap)[- _](?:dev|test)\b
```

---

## Step 4: Hostname allowlist

Add a configurable allowlist of known-safe patterns (like the URL allowlist):
```yaml
hostname_allowlist:
  - "^mapstruct-"
  - "^spring-boot-"
  - "-plugin$"
  - "^maven-"
```

Default list should include common Maven/Java ecosystem terms.

---

## Implementation Order

1. **Step 1** (structural filters) — highest ROI, zero false negative risk
2. **Step 3** (tighten suffixes) — removes `test` and `int` from suffix triggers
3. **Step 2** (tier prefixes) — requires more careful testing
4. **Step 4** (allowlist) — configurable escape hatch

Each step should be followed by re-running on the `urbafc-commun` report to verify reduction.

---

## Expected Impact

| Step | FP removed from sample | Risk of new FN |
|------|----------------------|----------------|
| 1 (structural filters) | ~8 of 13 | None |
| 2 (tier prefixes) | ~3 more | Low |
| 3 (tighten suffixes) | ~2 more | Low |
| 4 (allowlist) | Configurable | None |

Target: reduce false positives by 80%+ while keeping real hostnames detected.
