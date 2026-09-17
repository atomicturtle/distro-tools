"""Unit tests for CSAF SA / VEX / OpenVEX / OVAL / provider exports."""

import datetime
import unittest
from unittest.mock import Mock
from xml.etree import ElementTree as ET

from apollo.exports.csaf_sa import RockySACSAFGenerator, advisory_filename
from apollo.exports.csaf_vex import VexCSAFGenerator, VexProductEntry
from apollo.exports.openvex import build_openvex, csaf_vex_to_openvex
from apollo.exports.oval import build_oval_xml, oval_filename
from apollo.exports.provider import advisory_index, changes_csv_rows, provider_metadata


def _pkg(nevra, product_name="Rocky Linux 9"):
    pkg = Mock()
    pkg.nevra = nevra
    pkg.product_name = product_name
    pkg.package_name = nevra.split("-")[0]
    pkg.module_name = None
    pkg.module_stream = None
    return pkg


def _advisory():
    adv = Mock()
    adv.name = "RLSA-2024:1234"
    adv.synopsis = "curl security update"
    adv.description = "Fixed CVE-2024-0001"
    adv.topic = "An update is available"
    adv.kind = "Security"
    adv.severity = "Important"
    adv.published_at = datetime.datetime(2024, 6, 1, 12, 0, 0)
    adv.rocky_published_at = None
    adv.updated_at = datetime.datetime(2024, 6, 1, 12, 0, 0)
    rh = Mock()
    rh.name = "RHSA-2024:1234"
    adv.red_hat_advisory = rh
    adv.packages = [
        _pkg("curl-0:7.76.1-1.el9.x86_64"),
        _pkg("curl-0:7.76.1-1.el9.src"),
    ]
    cve = Mock()
    cve.cve = "CVE-2024-0001"
    cve.cvss3_base_score = "7.5"
    cve.cvss3_scoring_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    cve.cwe = "CWE-119"
    adv.cves = [cve]
    fix = Mock()
    fix.ticket_id = "12345"
    fix.source = "https://bugzilla.redhat.com/12345"
    fix.description = "curl: overflow"
    adv.fixes = [fix]
    return adv


class TestCsafSA(unittest.TestCase):
    def test_generate_keeps_rlsa_id(self):
        doc = RockySACSAFGenerator().generate(_advisory())
        self.assertEqual(doc["document"]["category"], "csaf_security_advisory")
        self.assertEqual(doc["document"]["tracking"]["id"], "RLSA-2024:1234")
        self.assertEqual(
            doc["document"]["publisher"]["name"],
            "Rocky Enterprise Software Foundation",
        )
        self.assertTrue(doc["vulnerabilities"])
        self.assertEqual(doc["vulnerabilities"][0]["cve"], "CVE-2024-0001")
        self.assertIn("product_tree", doc)
        self.assertEqual(advisory_filename("RLSA-2024:1234"), "rlsa-2024_1234.json")


class TestCsafVex(unittest.TestCase):
    def test_fail_closed_fixed_without_nevras(self):
        gen = VexCSAFGenerator()
        entries = [
            VexProductEntry(
                product_key="rocky:product:1",
                product_name="Rocky Linux",
                cpe_23=None,
                status="fixed",
                package_nevras=[],
            ),
            VexProductEntry(
                product_key="rocky:product:1",
                product_name="Rocky Linux",
                cpe_23="cpe:2.3:o:rocky:rocky_linux:9:*:*:*:*:*:*:*",
                status="not_shipped",
            ),
        ]
        doc = gen.generate("CVE-2024-0001", entries)
        status = doc["vulnerabilities"][0]["product_status"]
        self.assertNotIn("fixed", status)
        self.assertIn("known_not_affected", status)

    def test_fixed_with_nevras(self):
        gen = VexCSAFGenerator()
        entries = [
            VexProductEntry(
                product_key="rocky:product:1",
                product_name="Rocky Linux",
                cpe_23=None,
                status="fixed",
                package_nevras=["curl-0:7.76.1-1.el9.x86_64"],
                action_statement="Fixed in RLSA-2024:1234",
            )
        ]
        doc = gen.generate("CVE-2024-0001", entries)
        self.assertIn("fixed", doc["vulnerabilities"][0]["product_status"])
        self.assertTrue(doc["vulnerabilities"][0]["remediations"])


class TestOpenVex(unittest.TestCase):
    def test_build_openvex_purls(self):
        entries = [
            VexProductEntry(
                product_key="rocky:product:1",
                product_name="Rocky Linux",
                cpe_23=None,
                status="fixed",
                package_nevras=["curl-0:7.76.1-1.el9.x86_64"],
            )
        ]
        doc = build_openvex("CVE-2024-0001", entries)
        self.assertEqual(doc["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertEqual(doc["statements"][0]["status"], "fixed")
        self.assertTrue(
            doc["statements"][0]["products"][0]["@id"].startswith(
                "pkg:rpm/rockylinux/curl@"
            )
        )

    def test_csaf_to_openvex(self):
        csaf = {
            "document": {"tracking": {"id": "CVE-2024-0001"}},
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-0001",
                    "product_status": {
                        "fixed": ["rocky:product:1:curl-0:7.76.1-1.el9.x86_64"]
                    },
                }
            ],
        }
        doc = csaf_vex_to_openvex(csaf)
        self.assertEqual(doc["statements"][0]["status"], "fixed")


class TestOval(unittest.TestCase):
    def test_build_oval_xml(self):
        xml = build_oval_xml([_advisory()], 9)
        root = ET.fromstring(xml)
        self.assertTrue(root.tag.endswith("oval_definitions"))
        defs = list(root.iter())
        self.assertTrue(any("definition" in (el.tag or "") for el in defs))
        self.assertEqual(oval_filename(9), "org.rockylinux.rlsa-9.xml")

    def test_oval_skips_other_major(self):
        xml = build_oval_xml([_advisory()], 8)
        self.assertNotIn("RLSA-2024:1234", xml)


class TestProvider(unittest.TestCase):
    def test_provider_metadata(self):
        meta = provider_metadata(advisory_years=["2024", "2025"])
        self.assertEqual(meta["metadata_version"], "2.0")
        self.assertIn("publisher", meta)
        self.assertTrue(meta["distributions"])

    def test_changes_and_index(self):
        adv = _advisory()
        csv_text = changes_csv_rows([adv])
        self.assertIn("path,timestamp", csv_text)
        self.assertIn("advisories/2024/rlsa-2024_1234.json", csv_text)
        idx = advisory_index([adv])
        self.assertEqual(idx[0]["id"], "RLSA-2024:1234")
        self.assertEqual(idx[0]["path"], "advisories/2024/rlsa-2024_1234.json")


if __name__ == "__main__":
    unittest.main()
