"""Unit tests for Koji NVR mapping and rocky publish stamp guards."""

import datetime
import unittest

from apollo.koji.nvr import (
    nvr_from_nevra,
    rpm_nvras_from_nevras,
    source_nvrs_from_nevras,
)
from apollo.koji.sync import usable_rocky_stamp


class TestKojiNvr(unittest.TestCase):
    def test_src_nevra_to_nvr(self):
        nvr, arch = nvr_from_nevra(
            "java-25-openjdk-1:25.0.3.0.9-1.el10_1.src.rpm"
        )
        self.assertEqual(nvr, "java-25-openjdk-25.0.3.0.9-1.el10_1")
        self.assertEqual(arch, "src")

    def test_prefers_src_nvrs(self):
        nvrs = source_nvrs_from_nevras(
            [
                "java-25-openjdk-1:25.0.3.0.9-1.el10_1.x86_64.rpm",
                "java-25-openjdk-1:25.0.3.0.9-1.el10_1.src.rpm",
                "java-25-openjdk-headless-1:25.0.3.0.9-1.el10_1.x86_64.rpm",
            ]
        )
        self.assertEqual(nvrs, ["java-25-openjdk-25.0.3.0.9-1.el10_1"])

    def test_binary_fallback_nvra(self):
        nvras = rpm_nvras_from_nevras(
            ["bash-0:5.1.8-6.el9.x86_64.rpm"]
        )
        self.assertEqual(nvras, ["bash-5.1.8-6.el9.x86_64"])


class TestUsableRockyStamp(unittest.TestCase):
    def test_rejects_stamp_before_upstream(self):
        upstream = datetime.datetime(2026, 3, 24, 10, 56, 42, tzinfo=datetime.timezone.utc)
        early = datetime.datetime(2026, 2, 10, 16, 46, 5, tzinfo=datetime.timezone.utc)
        self.assertIsNone(usable_rocky_stamp(early, upstream))

    def test_accepts_stamp_on_or_after_upstream(self):
        upstream = datetime.datetime(2026, 3, 24, 10, 56, 42, tzinfo=datetime.timezone.utc)
        same = upstream
        later = datetime.datetime(2026, 3, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(usable_rocky_stamp(same, upstream), same)
        self.assertEqual(usable_rocky_stamp(later, upstream), later)

    def test_naive_compared_as_utc(self):
        upstream = datetime.datetime(2026, 3, 24, 10, 56, 42)
        early = datetime.datetime(2026, 2, 10, 16, 46, 5, tzinfo=datetime.timezone.utc)
        self.assertIsNone(usable_rocky_stamp(early, upstream))


if __name__ == "__main__":
    unittest.main()
