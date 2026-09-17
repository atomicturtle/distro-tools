"""Tests for first-admin setup secret env constant."""

import os
import re
import unittest


class TestSetupSecretEnv(unittest.TestCase):
    def test_setup_secret_env_name_in_login_module(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "server",
            "routes",
            "login.py",
        )
        source = open(path, encoding="utf-8").read()
        self.assertIn('SETUP_SECRET_ENV = "APOLLO_SETUP_SECRET"', source)
        self.assertRegex(
            source,
            re.compile(r"os\.environ\.get\(SETUP_SECRET_ENV\)"),
        )


if __name__ == "__main__":
    unittest.main()
