"""Tests for CSRF form-body token extraction and equality."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.csrf import csrf_tokens_match, token_from_body, _PROTECTED_PREFIXES


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


if __name__ == "__main__":
    unittest.main()
