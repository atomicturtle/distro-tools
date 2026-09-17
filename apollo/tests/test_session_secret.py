"""Tests for import-time session secret loading."""

import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.settings import load_session_secret


class TestLoadSessionSecret(unittest.TestCase):
    def test_prefers_apollo_secret_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret")
            secret = load_session_secret(
                environ={
                    "APOLLO_SECRET_KEY": " from-apollo ",
                    "SECRET_KEY": "from-secret",
                },
                persist_path=path,
            )
            self.assertEqual(secret, "from-apollo")
            self.assertFalse(os.path.exists(path))

    def test_falls_back_to_secret_key(self):
        secret = load_session_secret(
            environ={"SECRET_KEY": "legacy-env"},
            persist_path=os.path.join(tempfile.gettempdir(), "unused-secret"),
        )
        self.assertEqual(secret, "legacy-env")

    def test_reads_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("file-secret\n")
            secret = load_session_secret(environ={}, persist_path=path)
            self.assertEqual(secret, "file-secret")

    def test_generates_and_persists_mode_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret")
            first = load_session_secret(environ={}, persist_path=path)
            self.assertEqual(len(first), 64)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
            second = load_session_secret(environ={}, persist_path=path)
            self.assertEqual(first, second)

    def test_empty_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret")
            open(path, "w", encoding="utf-8").close()
            with self.assertRaises(RuntimeError):
                load_session_secret(environ={}, persist_path=path)


if __name__ == "__main__":
    unittest.main()
