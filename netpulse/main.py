"""Command-line entry point for netpulse-cli."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .core import ScanConfig, scanTargets
from .utils import normalizeTarget, writeReportFiles


def buildParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpulse",
        description="Fast website response, SSL aur security-header auditor.",
    )
    parser.add_argument("targets", nargs="*", help="Website URLs ya hostnames")
    parser.add_argument("-f", "--file", help="Newline-separated targets ki file")
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "both"),
        default="both",
        help="Report format (default: both)",
    )
    parser.add_argument("-o", "--output", default="reports", help="Report folder")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Concurrent scans")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Timeout seconds")
    return parser


def loadTargets(args: argparse.Namespace) -> list[str]:
    values = list(args.targets)
    if args.file:
        values.extend(
            line.strip()
            for line in Path(args.file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    clean = []
    seen = set()
    for value in values:
        target = normalizeTarget(value)
        if target and target not in seen:
            clean.append(target)
            seen.add(target)
    return clean


async def runScan(args: argparse.Namespace) -> int:
    targets = loadTargets(args)
    if not targets:
        print("[!] Koi valid target nahi mila. URL ya hostname provide karein.")
        return 2
    if args.concurrency < 1 or args.timeout <= 0:
        print("[!] Concurrency 1+ aur timeout positive number hona chahiye.")
        return 2

    print(f"[+] Website scan ho rahi hai: {len(targets)} target(s), concurrency {args.concurrency}.")
    results = await scanTargets(
        targets,
        ScanConfig(timeout=args.timeout, concurrency=args.concurrency),
    )
    for result in results:
        response = result.response
        sslInfo = result.ssl
        if result.error:
            print(f"[!] {result.target}: {result.error}")
            continue
        status = response.get("statusCode", "-")
        days = sslInfo.get("expiresInDays", "-")
        print(
            f"[+] {result.target}: HTTP {status}, "
            f"response {response.get('responseTimeMs', '-')} ms, SSL days left {days}."
        )
        if sslInfo.get("expired") or (isinstance(days, int) and days <= 30):
            print("    [!] Alert: SSL Certificate expire hone wala hai!")

    paths = writeReportFiles((item.toDict() for item in results), args.output, args.format)
    for path in paths:
        print(f"[+] Report ready hai: {path}")
    print("[+] Scan complete. Report ko review karke apni website harden karein.")
    return 0


def main() -> int:
    args = buildParser().parse_args()
    try:
        return asyncio.run(runScan(args))
    except FileNotFoundError as exc:
        print(f"[!] File nahi mili: {exc.filename}")
        return 2
    except KeyboardInterrupt:
        print("\n[!] Scan user ne stop kar di.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
