"""Tests for CSRF form-body token extraction and equality."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.csrf import (
    CSRFMiddleware,
    csrf_tokens_match,
    token_from_body,
    _PROTECTED_PREFIXES,
)


class TestCsrfTokenFromBody(unittest.TestCase):
    def test_urlencoded(self):
        body = b"name=mirror&csrf_token=abc123&other=1"
        self.assertEqual(
            token_from_body("application/x-www-form-urlencoded", body),
            "abc123",
        )

    def test_multipart(self):
        body = (
            b"------boundary\r\n"
            b'Content-Disposition: form-data; name="csrf_token"\r\n'
            b"\r\n"
            b"tok_value\r\n"
            b"------boundary--\r\n"
        )
        self.assertEqual(
            token_from_body("multipart/form-data; boundary=----boundary", body),
            "tok_value",
        )

    def test_match_rejects_length_mismatch(self):
        self.assertFalse(csrf_tokens_match("abc", "abcd"))
        self.assertTrue(csrf_tokens_match("abcd", "abcd"))

    def test_setup_path_is_protected(self):
        self.assertIn("/login/setup", _PROTECTED_PREFIXES)
        self.assertIn("/logout", _PROTECTED_PREFIXES)


class TestCsrfBodyLimit(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_oversized_protected_body(self):
        seen = {"status": None}

        async def app(scope, receive, send):  # pylint: disable=unused-argument
            raise AssertionError("downstream must not run")

        async def receive():
            return {
                "type": "http.request",
                "body": b"x" * 64,
                "more_body": False,
            }

        async def send(message):
            if message["type"] == "http.response.start":
                seen["status"] = message["status"]

        middleware = CSRFMiddleware(
            app,
            protected_prefixes=("/admin",),
            max_body_bytes=32,
        )
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/admin/supported-products/import",
            "headers": [],
            "query_string": b"",
            "session": {},
        }
        await middleware(scope, receive, send)
        self.assertEqual(seen["status"], 413)


if __name__ == "__main__":
    unittest.main()
