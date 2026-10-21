#!/usr/bin/env python3
"""
php2shell_check.py — multi-signal PASSIVE checker for CVE-2026-109618 /
CVE-2026-109619 ("php2shell").

This tool does NOT exploit anything and never triggers the vulnerable
code path. It only reads information the server already discloses:

  1. HTTP headers (X-Powered-By / Server) on several common paths
  2. A leaked phpinfo() page, if one is publicly reachable — this gives
     the REAL running PHP_VERSION and the actual php.ini value of
     session.upload_progress.enabled (the precondition for php2shell),
     not just a banner string.
  3. composer.lock / README files that sometimes leak PHP/framework
     version requirements.

Each signal is combined into an evidence list so a verdict is not based
on a single, spoofable header. This still cannot PROVE memory-corruption
exploitability without triggering it — that would be an actual exploit
attempt, which this tool deliberately does not do.

Usage:
    python php2shell_check.py <url>
    python php2shell_check.py -f targets.txt -o results.csv

Fixed (safe) versions: 8.5.12, 8.4.27, 8.3.36, 8.2.35
Reference: https://thephp.foundation/blog/2026/10/21/todays-php-security-release/

Authorized testing only. Use only on systems you own or have explicit
permission to test.
"""
import argparse
import csv
import json
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
PHP_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
PHPINFO_VER_RE = re.compile(r"PHP Version\s*</td>\s*<td[^>]*>\s*([\d.]+)", re.IGNORECASE)
PHPINFO_VER_RE2 = re.compile(r"PHP Version ([\d.]+)", re.IGNORECASE)
UPLOAD_PROGRESS_RE = re.compile(
    r"session\.upload_progress\.enabled.*?(On|Off|1|0)", re.IGNORECASE | re.DOTALL)
COMPOSER_PHP_RE = re.compile(r'"php"\s*:\s*"([^"]+)"')

PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/test.php", "/_phpinfo.php", "/php_info.php"]
BANNER_PATHS = ["/", "/index.php"]
LEAK_PATHS = ["/composer.lock", "/README.txt", "/readme.html"]

UA = {"User-Agent": "php2shell-check/2.0"}


def fetch(url, timeout):
    """Single harmless GET. Returns (status, headers_text, body_text) or None."""
    ctx = ssl._create_unverified_context()
    try:
        req = Request(url, method="GET", headers=UA)
        try:
            with urlopen(req, timeout=timeout, context=ctx) as resp:
                hdr = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                body = resp.read(200_000).decode("utf-8", errors="replace")
                return resp.status, hdr, body
        except HTTPError as e:
            hdr = "\n".join(f"{k}: {v}" for k, v in (e.headers or {}).items())
            body = e.read(200_000).decode("utf-8", errors="replace") if e.fp else ""
            return e.code, hdr, body
    except (URLError, socket.timeout, ConnectionError, OSError):
        return None


def parse_banner(headers_text):
    m = PHP_RE.search(headers_text)
    return tuple(int(x) for x in m.groups()) if m else None


def parse_phpinfo(body):
    """Extract real PHP_VERSION and upload_progress setting from a phpinfo() page."""
    m = PHPINFO_VER_RE.search(body) or PHPINFO_VER_RE2.search(body)
    ver = None
    if m:
        parts = m.group(1).split(".")[:3]
        try:
            ver = tuple(int(p) for p in parts)
        except ValueError:
            ver = None
    up = UPLOAD_PROGRESS_RE.search(body)
    upload_progress = up.group(1) if up else None
    return ver, upload_progress


def classify(ver):
    if ver is None:
        return "unknown", "no PHP version signal found"
    branch = (ver[0], ver[1])
    if branch in FIXED:
        return ("patched" if ver >= FIXED[branch] else "likely_vulnerable",
                f"branch {ver[0]}.{ver[1]}, fixed={'.'.join(map(str, FIXED[branch]))}")
    if branch < (8, 2):
        return "eol_or_unknown", "branch predates/outside the fixed set (no official patch)"
    return "unknown", f"unexpected branch {ver[0]}.{ver[1]}"


def check(base_url, timeout=8.0):
    base_url = base_url.rstrip("/")
    evidence = []
    best_ver = None
    best_source = None
    upload_progress = None
    reachable = False

    # 1) Banner on common pages
    for path in BANNER_PATHS:
        r = fetch(base_url + path, timeout)
        if r is None:
            continue
        reachable = True
        status, hdr, _ = r
        ver = parse_banner(hdr)
        if ver:
            evidence.append(f"header banner at {path} -> PHP/{'.'.join(map(str, ver))}")
            if best_ver is None:
                best_ver, best_source = ver, f"header:{path}"

    # 2) Leaked phpinfo() page — real php.ini values, not a spoofable header
    for path in PHPINFO_PATHS:
        r = fetch(base_url + path, timeout)
        if r is None:
            continue
        reachable = True
        status, hdr, body = r
        if status == 200 and ("phpinfo()" in body or "PHP Version" in body):
            ver, up = parse_phpinfo(body)
            if up:
                upload_progress = up
                evidence.append(f"phpinfo() at {path}: session.upload_progress.enabled={up}")
            if ver:
                evidence.append(f"phpinfo() at {path}: PHP Version {'.'.join(map(str, ver))} (authoritative)")
                best_ver, best_source = ver, f"phpinfo:{path}"  # phpinfo wins over header

    # 3) composer.lock / README leakage (weak signal, framework constraint not live version)
    for path in LEAK_PATHS:
        r = fetch(base_url + path, timeout)
        if r is None:
            continue
        reachable = True
        status, hdr, body = r
        if status == 200 and path.endswith(".lock"):
            m = COMPOSER_PHP_RE.search(body)
            if m:
                evidence.append(f"composer.lock requires php {m.group(1)} (constraint, not live version)")

    if not reachable:
        return {"url": base_url, "php_version": "", "verdict": "unreachable",
                "upload_progress": "", "evidence": "no endpoint responded"}

    verdict, note = classify(best_ver)
    if upload_progress in ("Off", "0"):
        note += " | session.upload_progress is Off -> primary attack vector mitigated"
    elif upload_progress in ("On", "1"):
        note += " | session.upload_progress is On (default, precondition present)"

    return {
        "url": base_url,
        "php_version": ".".join(map(str, best_ver)) if best_ver else "",
        "verdict": verdict,
        "upload_progress": upload_progress or "",
        "evidence": " ; ".join(evidence) if evidence else note,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Multi-signal passive checker for php2shell (CVE-2026-109618/109619)")
    ap.add_argument("url", nargs="?", help="Single target base URL (e.g. https://example.com)")
    ap.add_argument("-f", "--file", help="File with one URL/host per line")
    ap.add_argument("-o", "--out", help="CSV output path")
    ap.add_argument("--json", action="store_true", help="Print each result as JSON")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    targets.append(line if "://" in line else f"https://{line}")

    if not targets:
        ap.print_help()
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(check, t, args.timeout): t for t in targets}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if args.json:
                print(json.dumps(r))
            else:
                print(f"[{r['verdict']:16}] {r['url']}  PHP={r['php_version'] or '?'}  "
                      f"upload_progress={r['upload_progress'] or '?'}")
                print(f"    evidence: {r['evidence']}")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["url", "php_version", "verdict", "upload_progress", "evidence"])
            w.writeheader()
            w.writerows(results)
        print(f"\nSaved -> {args.out}")


if __name__ == "__main__":
    main()
