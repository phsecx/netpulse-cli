"""Small helpers for input validation and human-readable audit reports."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def normalizeTarget(value: str) -> str | None:
    """Return a normalized HTTP(S) URL or None when the input is unsafe or invalid."""

    raw = value.strip()
    if not raw:
        return None
    target = raw if URL_PATTERN.match(raw) else f"https://{raw}"
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return target.rstrip("/")


def resultLabel(result: dict[str, Any]) -> str:
    """Create a short status label for terminal output."""

    if result.get("error"):
        return "ERROR"
    sslInfo = result.get("ssl", {})
    response = result.get("response", {})
    if sslInfo.get("expired") or (sslInfo.get("expiresInDays") is not None and sslInfo["expiresInDays"] <= 30):
        return "ALERT"
    if response.get("statusCode", 0) >= 400:
        return "WARNING"
    return "OK"


def markdownReport(results: Iterable[dict[str, Any]], createdAt: str | None = None) -> str:
    """Render audit results into a portable Markdown report."""

    rows = list(results)
    created = createdAt or datetime.now(timezone.utc).isoformat()
    lines = [
        "# Netpulse CLI Security Audit",
        "",
        f"> Report generated: `{created}`",
        "",
        "Netpulse audited the website response, SSL certificate, and security headers.",
        "",
        "## Summary",
        "",
        "| Target | HTTP | Response | SSL | SSL Days Left | Headers | Status |",
        "| --- | ---: | --- | --- | ---: | ---: | --- |",
    ]
    for item in rows:
        response = item.get("response", {})
        sslInfo = item.get("ssl", {})
        headerInfo = item.get("headers", {})
        status = resultLabel(item)
        lines.append(
            "| {target} | {http} | {responseState} | {sslState} | {days} | {score}% | {status} |".format(
                target=item.get("target", "-"),
                http=response.get("statusCode", "-"),
                responseState="Reachable" if response.get("ok") else response.get("error", "Unreachable"),
                sslState=("Valid" if sslInfo.get("secure") else sslInfo.get("error", "Not checked")),
                days=sslInfo.get("expiresInDays", "-"),
                score=headerInfo.get("score", 0),
                status=status,
            )
        )

    lines.extend(["", "## Detailed Findings", ""])
    for item in rows:
        target = item.get("target", "Unknown target")
        response = item.get("response", {})
        sslInfo = item.get("ssl", {})
        headerInfo = item.get("headers", {})
        lines.extend([f"### {target}", ""])
        if item.get("error"):
            lines.extend([f"**[!] Alert:** {item['error']}", ""])
        lines.extend([
            f"**Website:** {response.get('statusCode', '-')} status, "
            f"{response.get('responseTimeMs', '-')} ms response time.",
            "",
            f"**SSL:** {sslInfo.get('message', sslInfo.get('error', 'Not checked'))}.",
            "",
            "| Header | Result |",
            "| --- | --- |",
        ])
        for check in headerInfo.get("checks", {}).values():
            lines.append(f"| {check['header']} | {'Present' if check['present'] else 'Missing'} |")
        lines.extend(["", "---", ""])
    return "\n".join(lines).rstrip() + "\n"


def jsonReport(results: Iterable[dict[str, Any]], createdAt: str | None = None) -> str:
    """Render audit results into stable, indented JSON."""

    created = createdAt or datetime.now(timezone.utc).isoformat()
    payload = {
        "tool": "netpulse-cli",
        "createdAt": created,
        "results": list(results),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def writeReportFiles(
    results: Iterable[dict[str, Any]],
    outputDir: str | Path,
    reportFormat: str,
) -> list[Path]:
    """Write requested report formats and return their paths."""

    targetDir = Path(outputDir)
    targetDir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rows = list(results)
    paths: list[Path] = []
    if reportFormat in {"markdown", "both"}:
        path = targetDir / f"netpulse-report-{stamp}.md"
        path.write_text(markdownReport(rows), encoding="utf-8")
        paths.append(path)
    if reportFormat in {"json", "both"}:
        path = targetDir / f"netpulse-report-{stamp}.json"
        path.write_text(jsonReport(rows), encoding="utf-8")
        paths.append(path)
    return paths
