"""Tests that logout clears session state and drops the session cookie."""

import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.logout import logout


class TestLogout(unittest.IsolatedAsyncioTestCase):
    async def test_clears_session_and_deletes_cookie(self):
        request = MagicMock()
        request.session = {
            "user": 1,
            "user.name": "admin",
            "user.role": "admin",
            "csrf_token": "keep-me-not",
        }
        response = await logout(request)
        self.assertEqual(request.session, {})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers.get("location"), "/")
        set_cookie = response.headers.get("set-cookie", "")
        self.assertIn("session=", set_cookie)
        self.assertIn("Max-Age=0", set_cookie)


if __name__ == "__main__":
    unittest.main()
