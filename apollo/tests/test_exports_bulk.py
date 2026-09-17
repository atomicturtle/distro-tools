"""Unit tests for Apollo bulk errata.json export."""

import datetime
import unittest
from unittest.mock import Mock

from apollo.exports.bulk import (
    advisory_to_errata,
    build_errata_dump,
    product_matches_major,
)


def _pkg(nevra, product_name, package_name=None, checksum="abc", checksum_type="sha256"):
    pkg = Mock()
    pkg.nevra = nevra
    pkg.product_name = product_name
    pkg.package_name = package_name or nevra.split("-")[0]
    pkg.checksum = checksum
    pkg.checksum_type = checksum_type
    return pkg


def _advisory():
    adv = Mock()
    adv.name = "RLSA-2024:1234"
    adv.synopsis = "curl security update"
    adv.description = "Fixed CVE-2024-0001"
    adv.topic = "An update is available"
    adv.kind = "Security"
    adv.severity = "Important"
    adv.reboot_suggested = False
    adv.published_at = datetime.datetime(2024, 6, 1, 12, 0, 0)
    adv.rocky_published_at = datetime.datetime(2024, 6, 2, 12, 0, 0)
    adv.updated_at = datetime.datetime(2024, 6, 2, 12, 0, 0)
    rh = Mock()
    rh.name = "RHSA-2024:1234"
    adv.red_hat_advisory = rh
    adv.packages = [
        _pkg(
            "curl-0:7.76.1-1.el9.x86_64",
            "Rocky Linux 9",
            package_name="curl",
        ),
        _pkg(
            "curl-0:7.76.1-1.el9.src",
            "Rocky Linux 9",
            package_name="curl",
        ),
        _pkg(
            "curl-0:7.76.1-1.el8.x86_64",
            "Rocky Linux 8",
            package_name="curl",
        ),
    ]
    cve = Mock()
    cve.cve = "CVE-2024-0001"
    adv.cves = [cve]
    fix = Mock()
    fix.ticket_id = "12345"
    fix.source = "https://bugzilla.redhat.com/12345"
    fix.description = "curl: overflow"
    adv.fixes = [fix]
    return adv


class TestBulkExport(unittest.TestCase):
    def test_product_matches_major(self):
        self.assertTrue(product_matches_major("Rocky Linux 9", 9))
        self.assertTrue(product_matches_major("Rocky Linux 9 x86_64", 9))
        self.assertFalse(product_matches_major("Rocky Linux 8", 9))
        self.assertFalse(product_matches_major("Rocky Linux 90", 9))

    def test_advisory_to_errata_filters_major(self):
        item = advisory_to_errata(_advisory(), 9)
        self.assertIsNotNone(item)
        self.assertEqual(item["updateinfo_id"], "RLSA-2024:1234")
        self.assertEqual(item["type"], "security")
        self.assertEqual(item["severity"], "Important")
        pkgs = item["pkglist"]["packages"]
        self.assertEqual(len(pkgs), 2)
        arches = {p["arch"] for p in pkgs}
        self.assertEqual(arches, {"x86_64", "src"})
        binary = next(p for p in pkgs if p["arch"] == "x86_64")
        self.assertEqual(binary["src"], "curl-7.76.1-1.el9.src.rpm")
        self.assertTrue(
            any(r["type"] == "cve" and r["id"] == "CVE-2024-0001" for r in item["references"])
        )
        self.assertTrue(any(r["type"] == "rhsa" for r in item["references"]))

    def test_build_errata_dump_skips_empty(self):
        adv = _advisory()
        adv.packages = [
            _pkg("curl-0:7.76.1-1.el8.x86_64", "Rocky Linux 8", "curl"),
        ]
        out = build_errata_dump([adv], 9)
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
