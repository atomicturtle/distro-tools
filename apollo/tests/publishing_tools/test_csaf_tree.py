"""Tests for CSAF provider tree writer (no DB required)."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from apollo.exports.provider import (
    advisory_relpath,
    index_txt,
    path_timestamp_csv,
    provider_metadata,
    vex_relpath,
)
from apollo.publishing_tools.csaf_tree import TreeDocument, write_tree_documents
from apollo.publishing_tools.csaf_archives import build_track_archive


class TestProviderHelpers(unittest.TestCase):
    def test_index_and_csv(self):
        self.assertEqual(
            index_txt(["2024/b.json", "2024/a.json", "2024/a.json"]),
            "2024/a.json\n2024/b.json\n",
        )
        csv_text = path_timestamp_csv(
            [
                (
                    "2024/rlsa-2024_1.json",
                    datetime(2024, 1, 2, tzinfo=timezone.utc),
                )
            ]
        )
        self.assertIn("2024/rlsa-2024_1.json", csv_text)
        self.assertNotIn("path,timestamp", csv_text)

    def test_relpaths(self):
        self.assertEqual(
            advisory_relpath("RLSA-2024:1234"), "2024/rlsa-2024_1234.json"
        )
        self.assertEqual(vex_relpath("CVE-2024-0001"), "2024/cve-2024-0001.json")


class TestCsafArchives(unittest.TestCase):
    def test_build_track_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            track = Path(tmp) / "advisories"
            year = track / "2024"
            year.mkdir(parents=True)
            (year / "rlsa-2024_1.json").write_text("{}\n", encoding="utf-8")
            (track / "index.txt").write_text(
                "2024/rlsa-2024_1.json\n", encoding="utf-8"
            )
            archive = build_track_archive(track, "advisories")
            self.assertIsNotNone(archive)
            self.assertTrue(archive.is_file())
            self.assertTrue(Path(str(archive) + ".sha256").is_file())
            latest = (
                track / "archive_latest.txt"
            ).read_text(encoding="utf-8").strip()
            self.assertEqual(latest, archive.name)
            self.assertTrue(latest.endswith(".tar.zst"))


class TestCsafTreeWriter(unittest.TestCase):
    def test_write_full_tree(self):
        adv = TreeDocument(
            relpath="2024/rlsa-2024_1234.json",
            document={
                "document": {
                    "category": "csaf_security_advisory",
                    "tracking": {"id": "RLSA-2024:1234"},
                }
            },
            changed_at=datetime(2024, 6, 2, tzinfo=timezone.utc),
            released_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )
        vex = TreeDocument(
            relpath="2024/cve-2024-0001.json",
            document={
                "document": {
                    "category": "csaf_vex",
                    "tracking": {"id": "CVE-2024-0001"},
                }
            },
            changed_at=datetime(2024, 6, 3, tzinfo=timezone.utc),
            released_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = write_tree_documents(
                tmp,
                advisories=[adv],
                vex_documents=[vex],
                base_url="https://example.test/csaf/v2",
                prefix="csaf/v2",
            )
            self.assertEqual(root, Path(tmp) / "csaf" / "v2")

            adv_path = root / "advisories" / "2024" / "rlsa-2024_1234.json"
            vex_path = root / "vex" / "2024" / "cve-2024-0001.json"
            self.assertTrue(adv_path.is_file())
            self.assertTrue(vex_path.is_file())

            index = (root / "advisories" / "index.txt").read_text(
                encoding="utf-8"
            )
            self.assertEqual(index, "2024/rlsa-2024_1234.json\n")

            changes = (root / "advisories" / "changes.csv").read_text(
                encoding="utf-8"
            )
            self.assertIn("2024/rlsa-2024_1234.json", changes)

            self.assertEqual(
                (root / "advisories" / "deletions.csv").read_text(
                    encoding="utf-8"
                ),
                "",
            )
            self.assertTrue((root / "vex" / "releases.csv").is_file())

            meta = json.loads(
                (root / "provider-metadata.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                meta["canonical_url"],
                "https://example.test/csaf/v2/provider-metadata.json",
            )
            urls = [d["directory_url"] for d in meta["distributions"]]
            self.assertIn("https://example.test/csaf/v2/advisories/", urls)
            self.assertIn("https://example.test/csaf/v2/vex/", urls)
            self.assertIn(
                "https://example.test/csaf/v2/advisories/2024/", urls
            )

            body = json.loads(adv_path.read_text(encoding="utf-8"))
            self.assertEqual(
                body["document"]["tracking"]["id"], "RLSA-2024:1234"
            )

    def test_provider_metadata_years(self):
        meta = provider_metadata(
            advisory_years=["2025"],
            vex_years=["2024"],
            base_url="https://mirror.example/csaf/v2",
        )
        urls = [d["directory_url"] for d in meta["distributions"]]
        self.assertIn("https://mirror.example/csaf/v2/vex/2024/", urls)


if __name__ == "__main__":
    unittest.main()
