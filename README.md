# 🛡️ php2shell Passive Checker

![PHP](https://img.shields.io/badge/PHP-5.4%20--%208.5-777bb3?logo=php&logoColor=white)
![CVE](https://img.shields.io/badge/CVE-2026--109618%20%7C%20109619-critical)
![CVSS](https://img.shields.io/badge/CVSS-9.2-red)
![License](https://img.shields.io/badge/scope-authorized%20testing%20only-blue)
![No Exploit](https://img.shields.io/badge/payload-none%20%E2%80%94%20passive%20only-success)

**Zero-risk, one-request inventory tool for php2shell (CVE-2026-109618 / CVE-2026-109619)** — the critical (CVSS 9.2) unauthenticated PHP core RCE pair patched by the PHP Foundation on **2026-10-21**.

No exploit payloads. No multipart tricks. No crashes. Just a single harmless GET request, a header read, and a clear verdict — safe to run against your entire fleet in minutes.

---

## Why this exists

Within hours of php2shell's disclosure, dozens of exploit PoCs hit GitHub — most need lab-specific memory offsets or crash production workers just to "maybe" prove the bug. None of that helps you answer the first real question:

> **"Which of our hundreds of PHP hosts are even running a vulnerable version?"**

This tool answers exactly that, passively, at scale, with zero blast radius.

## Quick start

```bash
# Single target
python php2shell_check.py https://example.com/index.php

# Entire fleet, from a file (one host/URL per line)
python php2shell_check.py -f targets.txt -o results.csv --workers 20
```

Sample output:

```
[likely_vulnerable] https://old-app.example.com/   PHP 8.3.12   branch 8.3, fixed=8.3.36
[patched          ] https://api.example.com/       PHP 8.4.27   branch 8.4, fixed=8.4.27
[eol_or_unknown   ] https://legacy.example.com/     PHP 5.4.16   branch predates the fixed set
[unknown          ] https://cdn.example.com/        —            no PHP version banner
```

## Verdicts

| Verdict | Meaning |
|---|---|
| 🔴 `likely_vulnerable` | Banner shows a patch level **below** the emergency fix for that branch |
| 🟢 `patched` | At or above 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| 🟠 `eol_or_unknown` | Branch predates the fixed set entirely — **no official patch exists** |
| ⚪ `unknown` | No PHP banner in the response (`expose_php=Off`, CDN, WAF…) |
| ⚫ `unreachable` | No usable HTTP response |

## Fixed versions

**8.5.12 · 8.4.27 · 8.3.36 · 8.2.35** — released 2026-10-21.
📖 [PHP Foundation announcement](https://thephp.foundation/blog/2026/10/21/todays-php-security-release/)

## Limitations — read before you trust a result

- A version banner is **a signal, not a proof**. CDNs and `expose_php=Off` hide it; distro backports can patch the CVE while keeping an old-looking version string.
- For a conclusive answer on any single host, confirm with `php -v` or the package manager's changelog **on the host itself**.
- Can't patch right now? The documented interim mitigation is `session.upload_progress.enabled = Off`.

## Contributing

Found a banner format this misses, or a distro backport quirk? PRs and issues welcome.

## Scope

Authorized testing / asset inventory only. Use only on systems you own or have explicit permission to test. This tool performs **no exploitation** — see [`php2shell_check.py`](php2shell_check.py), it's ~100 lines, read it yourself.

---

⭐ If this saved you from running a crash-prone exploit PoC against prod just to check version numbers, star the repo.
