"""Unit tests for NVD 2.0 vulnerability parsing."""

import unittest

from apollo.nvd.client import parse_nvd_vulnerability


SAMPLE = {
    "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2025-10-27T17:05:46.460",
        "descriptions": [
            {"lang": "en", "value": "Apache Log4j2 JNDI injection."},
            {"lang": "es", "value": "Ignorar."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                        ),
                    },
                }
            ],
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.3,
                        "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                    },
                }
            ],
        },
        "weaknesses": [
            {
                "description": [
                    {"lang": "en", "value": "CWE-502"},
                    {"lang": "en", "value": "CWE-400"},
                ]
            }
        ],
        "references": [
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "source": "nvd@nist.gov",
                "tags": ["Vendor Advisory"],
            }
        ],
    }
}


class TestParseNvdVulnerability(unittest.TestCase):
    def test_extracts_cvss_cwe_refs(self):
        fields = parse_nvd_vulnerability(SAMPLE)
        self.assertEqual(fields["cve_id"], "CVE-2021-44228")
        self.assertIn("Log4j2", fields["description"])
        self.assertEqual(fields["cvss_v3_score"], "10.0")
        self.assertTrue(fields["cvss_v3_vector"].startswith("CVSS:3.1/"))
        self.assertEqual(fields["cvss_v2_score"], "9.3")
        self.assertEqual(fields["cwe"], "CWE-502, CWE-400")
        self.assertEqual(len(fields["refs"]), 1)
        self.assertIn("nvd.nist.gov", fields["refs"][0]["url"])
        self.assertIsNotNone(fields["published_at"])
        self.assertIsNotNone(fields["last_modified_at"])


if __name__ == "__main__":
    unittest.main()
