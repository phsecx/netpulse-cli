"""Asynchronous website and SSL auditing engine for netpulse-cli."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .utils import normalizeTarget


@dataclass(slots=True)
class ScanConfig:
    """Runtime settings used by the auditor."""

    timeout: float = 10.0
    concurrency: int = 20
    userAgent: str = "netpulse-cli/1.0"


@dataclass(slots=True)
class AuditResult:
    """Complete result for one target."""

    target: str
    checkedAt: str
    response: dict[str, Any] = field(default_factory=dict)
    ssl: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def toDict(self) -> dict[str, Any]:
        return asdict(self)


async def fetchResponse(
    target: str,
    session: aiohttp.ClientSession,
) -> dict[str, Any]:
    """Fetch a target and inspect its HTTP response without downloading the full body."""

    started = time.perf_counter()
    try:
        async with session.get(target, allow_redirects=True) as response:
            await response.content.read(8192)
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            headerMap = {key.lower(): value for key, value in response.headers.items()}
            return {
                "ok": True,
                "statusCode": response.status,
                "reason": response.reason,
                "finalUrl": str(response.url),
                "responseTimeMs": elapsed,
                "contentType": headerMap.get("content-type", ""),
                "contentLength": headerMap.get("content-length"),
                "headerMap": headerMap,
                "redirected": str(response.url) != target,
            }
    except asyncio.TimeoutError:
        return {
            "ok": False,
            "error": "Request timed out",
            "responseTimeMs": round((time.perf_counter() - started) * 1000, 2),
        }
    except aiohttp.ClientError as exc:
        return {
            "ok": False,
            "error": f"No HTTP response received: {exc.__class__.__name__}",
            "responseTimeMs": round((time.perf_counter() - started) * 1000, 2),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Unexpected HTTP response error: {exc.__class__.__name__}",
            "responseTimeMs": round((time.perf_counter() - started) * 1000, 2),
        }


def parseCertDate(value: str | None) -> str | None:
    """Convert an OpenSSL certificate date into an ISO-8601 timestamp."""

    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return value


async def checkSsl(target: str, timeout: float) -> dict[str, Any]:
    """Open a verified TLS connection and inspect the certificate validity dates."""

    parsed = urlparse(target)
    if parsed.scheme != "https":
        return {"checked": False, "secure": False, "message": "HTTPS is not in use"}

    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return {"checked": False, "secure": False, "message": "Hostname is missing"}

    context = ssl.create_default_context()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=context,
                server_hostname=host,
            ),
            timeout=timeout,
        )
        del reader
        sslObject = writer.get_extra_info("ssl_object")
        cert = sslObject.getpeercert() if sslObject else {}
        notAfter = parseCertDate(cert.get("notAfter"))
        notBefore = parseCertDate(cert.get("notBefore"))
        expiresInDays: int | None = None
        expired = False
        if notAfter:
            expiryDate = datetime.fromisoformat(notAfter)
            expiresInDays = (expiryDate - datetime.now(timezone.utc)).days
            expired = expiryDate <= datetime.now(timezone.utc)
        return {
            "checked": True,
            "secure": not expired,
            "expired": expired,
            "notBefore": notBefore,
            "notAfter": notAfter,
            "expiresInDays": expiresInDays,
            "issuer": cert.get("issuer", ""),
            "subject": cert.get("subject", ""),
            "message": "SSL certificate is valid" if not expired else "SSL certificate has expired",
        }
    except asyncio.TimeoutError:
        return {"checked": True, "secure": False, "error": "SSL handshake timed out"}
    except (OSError, socket.gaierror) as exc:
        return {
            "checked": True,
            "secure": False,
            "error": f"SSL connection failed: {exc.__class__.__name__}",
        }
    except Exception as exc:
        return {
            "checked": True,
            "secure": False,
            "error": f"SSL audit failed: {exc.__class__.__name__}",
        }
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def auditHeaders(headers: dict[str, Any], target: str) -> dict[str, Any]:
    """Audit the required security headers and add HTTPS-aware HSTS guidance."""

    checks = {
        "hsts": {
            "present": "strict-transport-security" in headers,
            "header": "Strict-Transport-Security",
        },
        "csp": {
            "present": "content-security-policy" in headers,
            "header": "Content-Security-Policy",
        },
        "xFrameOptions": {
            "present": "x-frame-options" in headers,
            "header": "X-Frame-Options",
        },
    }
    if urlparse(target).scheme != "https":
        checks["hsts"]["message"] = "HSTS is ineffective without HTTPS"
    else:
        checks["hsts"]["message"] = "HSTS is enabled" if checks["hsts"]["present"] else "HSTS is missing"

    presentCount = sum(1 for item in checks.values() if item["present"])
    return {
        "checks": checks,
        "presentCount": presentCount,
        "totalCount": len(checks),
        "score": round(presentCount / len(checks) * 100),
    }


async def scanTarget(
    target: str,
    config: ScanConfig,
    session: aiohttp.ClientSession,
) -> AuditResult:
    """Run all checks for one normalized target concurrently."""

    checkedAt = datetime.now(timezone.utc).isoformat()
    normalized = normalizeTarget(target)
    if not normalized:
        return AuditResult(
            target=target,
            checkedAt=checkedAt,
            error="Target is not a valid URL",
        )

    responseTask = asyncio.create_task(fetchResponse(normalized, session))
    sslTask = asyncio.create_task(checkSsl(normalized, config.timeout))
    response, sslInfo = await asyncio.gather(responseTask, sslTask)
    headers = response.get("headerMap", {})
    error = None if response.get("ok") else response.get("error")
    return AuditResult(
        target=normalized,
        checkedAt=checkedAt,
        response=response,
        ssl=sslInfo,
        headers=auditHeaders(headers, normalized),
        error=error,
    )


async def scanTargets(
    targets: list[str],
    config: ScanConfig | None = None,
) -> list[AuditResult]:
    """Scan targets concurrently while respecting the configured concurrency limit."""

    settings = config or ScanConfig()
    connector = aiohttp.TCPConnector(limit=0, ssl=False, enable_cleanup_closed=True)
    timeout = aiohttp.ClientTimeout(total=settings.timeout)
    headers = {"User-Agent": settings.userAgent, "Accept": "text/html,application/xhtml+xml"}
    semaphore = asyncio.Semaphore(max(1, settings.concurrency))

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=headers,
    ) as session:
        async def runOne(target: str) -> AuditResult:
            async with semaphore:
                return await scanTarget(target, settings, session)

        return list(await asyncio.gather(*(runOne(target) for target in targets)))
