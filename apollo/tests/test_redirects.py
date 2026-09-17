"""Tests for same-origin redirect helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.redirects import safe_relative_redirect


class TestSafeRelativeRedirect(unittest.TestCase):
    def test_allows_relative_paths(self):
        self.assertEqual(safe_relative_redirect("/admin/"), "/admin/")
        self.assertEqual(safe_relative_redirect("/?q=1"), "/?q=1")

    def test_rejects_absolute_and_protocol_relative(self):
        self.assertEqual(safe_relative_redirect("https://evil.example/phish"), "/")
        self.assertEqual(safe_relative_redirect("//evil.example/phish"), "/")
        self.assertEqual(safe_relative_redirect("http://evil.example"), "/")

    def test_fallback_for_empty(self):
        self.assertEqual(safe_relative_redirect(None), "/")
        self.assertEqual(safe_relative_redirect(""), "/")
        self.assertEqual(safe_relative_redirect("  "), "/")


if __name__ == "__main__":
    unittest.main()
