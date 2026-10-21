# php2shell Passive Checker

Passive (non-exploit) version checker for **CVE-2026-109618 / CVE-2026-109619**
("php2shell") — two critical PHP core vulnerabilities disclosed/patched on
2026-10-21 (CVSS 9.2).

This tool sends a single harmless HTTP GET request and reads the PHP
version from response headers (`X-Powered-By` / `Server`). **It does not
send exploit payloads, does not attempt RCE, and does not modify the
target in any way.**

## Why

A version banner alone does not prove exploitability (the header can be
hidden, spoofed, or out of sync with vendor backports), but it is a safe,
zero-risk first signal for inventory and triage across many hosts.

## Usage

```bash
# Single target
python php2shell_check.py https://example.com/index.php

# Bulk, from a file (one host/URL per line)
python php2shell_check.py -f targets.txt -o results.csv
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `likely_vulnerable` | Banner shows a full patch level below the emergency fix for that branch |
| `patched` | At or above 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| `eol_or_unknown` | Branch predates the fixed set (no official patch exists) |
| `unknown` | No PHP banner in the response (e.g. `expose_php=Off`, CDN) |
| `unreachable` | No usable HTTP response |

## Fixed versions

8.5.12 · 8.4.27 · 8.3.36 · 8.2.35 — released 2026-10-21.
Reference: [PHP Foundation announcement](https://thephp.foundation/blog/2026/10/21/todays-php-security-release/)

## Limitations

- CDNs and `expose_php=Off` hide the banner — `unknown` is **not** the same
  as "safe".
- Distro-backported builds may keep an old version string even when
  patched — confirm with `php -v` / package changelog on the host itself
  for a conclusive result.
- `session.upload_progress.enabled = Off` is the documented interim
  mitigation if you cannot patch immediately.

## Scope

Authorized testing / asset inventory only. Use only on systems you own or
have explicit permission to test. This tool performs no exploitation.
