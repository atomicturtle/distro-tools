"""Unit tests for Koji NVR mapping."""

import unittest

from apollo.koji.nvr import (
    nvr_from_nevra,
    rpm_nvras_from_nevras,
    source_nvrs_from_nevras,
)


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


if __name__ == "__main__":
    unittest.main()
