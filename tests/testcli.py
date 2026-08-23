import asyncio
import json
import unittest
from types import SimpleNamespace

from netpulse.core import auditHeaders, fetchResponse, scanTarget
from netpulse.utils import jsonReport, markdownReport, normalizeTarget


class FakeBody:
    async def read(self, limit):
        del limit
        return b"ok"


class FakeResponse:
    status = 200
    reason = "OK"
    url = "http://example.test"
    headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
    }
    content = FakeBody()

    async def __aenter__(self):
        return self

    async def __aexit__(self, excType, exc, trace):
        return False


class FakeSession:
    def get(self, target, allow_redirects=True):
        del target, allow_redirects
        return FakeResponse()


class NetpulseTests(unittest.TestCase):
    def test_normalizeTarget(self):
        self.assertEqual(normalizeTarget("example.com"), "https://example.com")
        self.assertEqual(normalizeTarget("http://example.com/"), "http://example.com")
        self.assertIsNone(normalizeTarget("ftp://example.com"))
        self.assertIsNone(normalizeTarget("https://user:pass@example.com"))

    def test_auditHeaders(self):
        result = auditHeaders(
            {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            },
            "https://example.com",
        )
        self.assertEqual(result["score"], 67)
        self.assertTrue(result["checks"]["hsts"]["present"])
        self.assertFalse(result["checks"]["xFrameOptions"]["present"])

    def test_fetchResponse(self):
        result = asyncio.run(fetchResponse("http://example.test", FakeSession()))
        self.assertTrue(result["ok"])
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["contentType"], "text/html")

    def test_scanTarget(self):
        config = SimpleNamespace(timeout=1, concurrency=1, userAgent="test")
        result = asyncio.run(scanTarget("http://example.test", config, FakeSession()))
        self.assertEqual(result.target, "http://example.test")
        self.assertEqual(result.response["statusCode"], 200)
        self.assertEqual(result.headers["score"], 67)
        self.assertFalse(result.ssl["checked"])

    def test_reports_are_serializable(self):
        rows = [{
            "target": "https://example.com",
            "checkedAt": "2026-01-01T00:00:00+00:00",
            "response": {"ok": True, "statusCode": 200, "responseTimeMs": 20},
            "ssl": {"secure": True, "expiresInDays": 90, "message": "SSL certificate is valid"},
            "headers": {"score": 100, "checks": {}},
            "error": None,
        }]
        self.assertIn("# Netpulse CLI Security Audit", markdownReport(rows))
        payload = json.loads(jsonReport(rows))
        self.assertEqual(payload["tool"], "netpulse-cli")
        self.assertEqual(payload["results"][0]["response"]["statusCode"], 200)


if __name__ == "__main__":
    unittest.main()
