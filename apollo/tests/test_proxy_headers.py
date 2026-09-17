"""Tests for ForwardedProtoMiddleware used on older Starlette."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.proxy_headers import ForwardedProtoMiddleware


class TestForwardedProtoMiddleware(unittest.IsolatedAsyncioTestCase):
    async def test_sets_scheme_from_x_forwarded_proto(self):
        seen = {}

        async def app(scope, receive, send):  # pylint: disable=unused-argument
            seen["scheme"] = scope["scheme"]

        middleware = ForwardedProtoMiddleware(app)
        scope = {
            "type": "http",
            "scheme": "http",
            "headers": [(b"x-forwarded-proto", b"https")],
        }
        await middleware(scope, None, None)
        self.assertEqual(seen["scheme"], "https")


if __name__ == "__main__":
    unittest.main()
