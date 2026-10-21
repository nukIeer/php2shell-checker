#!/usr/bin/env python3
"""
php2shell_check.py — PASSIVE version checker for CVE-2026-109618 / CVE-2026-109619 ("php2shell").

This tool does NOT exploit anything. It sends a single harmless HTTP GET
request to the target and reads the PHP version from response headers
(X-Powered-By / Server), then compares it against the versions PHP fixed
on 2026-10-21.

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
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
PHP_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)


def parse_version(headers_text):
    m = PHP_RE.search(headers_text)
    return tuple(int(x) for x in m.groups()) if m else None


def classify(ver):
    if ver is None:
        return "unknown", "no PHP version banner (expose_php off, CDN, …)"
    branch = (ver[0], ver[1])
    if branch in FIXED:
        return ("patched" if ver >= FIXED[branch] else "likely_vulnerable",
                f"branch {ver[0]}.{ver[1]}, fixed={'.'.join(map(str, FIXED[branch]))}")
    if branch < (8, 2):
        return "eol_or_unknown", "branch predates/outside the fixed set (no official patch)"
    return "unknown", f"unexpected branch {ver[0]}.{ver[1]}"


def check(url, timeout=8.0):
    ctx = ssl._create_unverified_context()
    try:
        req = Request(url, method="GET", headers={"User-Agent": "php2shell-check/1.0"})
        try:
            with urlopen(req, timeout=timeout, context=ctx) as resp:
                hdr = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                status = resp.status
        except HTTPError as e:
            hdr = "\n".join(f"{k}: {v}" for k, v in (e.headers or {}).items())
            status = e.code
    except (URLError, socket.timeout, ConnectionError, OSError) as e:
        return {"url": url, "status": "", "php_version": "", "verdict": "unreachable", "note": str(e)}

    ver = parse_version(hdr)
    verdict, note = classify(ver)
    return {"url": url, "status": status,
            "php_version": ".".join(map(str, ver)) if ver else "",
            "verdict": verdict, "note": note}


def main():
    ap = argparse.ArgumentParser(description="Passive PHP version check for php2shell (CVE-2026-109618/109619)")
    ap.add_argument("url", nargs="?", help="Single target URL")
    ap.add_argument("-f", "--file", help="File with one URL/host per line")
    ap.add_argument("-o", "--out", help="CSV output path")
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
                    targets.append(line if "://" in line else f"https://{line}/")

    if not targets:
        ap.print_help()
        sys.exit(1)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(check, t, args.timeout): t for t in targets}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            print(f"[{r['verdict']:16}] {r['url']}  {r['php_version']}  {r['note']}")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["url", "status", "php_version", "verdict", "note"])
            w.writeheader()
            w.writerows(results)
        print(f"\nSaved -> {args.out}")


if __name__ == "__main__":
    main()
