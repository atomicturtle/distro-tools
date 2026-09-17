"""Tests for StaticFilesSym path jail."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from common.fastapi import StaticFilesSym


class TestStaticFilesSymJail(unittest.TestCase):
    def test_blocks_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "static"
            root.mkdir()
            (root / "ok.txt").write_text("hi", encoding="utf-8")
            outside = Path(tmp) / "secret.txt"
            outside.write_text("nope", encoding="utf-8")

            files = StaticFilesSym(directory=str(root))
            ok_path, ok_stat = files.lookup_path("ok.txt")
            self.assertTrue(ok_path.endswith("ok.txt"))
            self.assertIsNotNone(ok_stat)

            escaped, escaped_stat = files.lookup_path("../secret.txt")
            self.assertEqual(escaped, "")
            self.assertIsNone(escaped_stat)


if __name__ == "__main__":
    unittest.main()
