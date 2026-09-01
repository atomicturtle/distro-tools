"""
Tests for RH matcher activities
"""

import unittest
import asyncio
import datetime
import sys
import os
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from common.info import Info

if Info._name is None:  # pylint: disable=protected-access
    Info("apollotest", "apollo2")

from apollo.rpmworker import repomd
from apollo.rpmworker.rh_matcher_activities import (
    advisory_clone_published_at,
    affected_product_rows_from_packages,
    create_or_update_advisory_packages,
    NewPackage,
    process_repomd,
    repo_arch_for_mirror,
    rh_advisory_matches_major,
    stream_product_name,
    _is_historical_mirror,
    _nvra_with_arch,
    _repomd_belongs_to_mirror,
    _repo_search_cleaned,
)

NS = "http://linux.duke.edu/metadata/common"
RPM_NS = "http://linux.duke.edu/metadata/rpm"


def _make_pkg_element(name, version, release, arch, epoch="0"):
    """Build a minimal repomd <package> XML element."""
    pkg = ET.Element(f"{{{NS}}}package")
    name_el = ET.SubElement(pkg, f"{{{NS}}}name")
    name_el.text = name
    ver_el = ET.SubElement(pkg, f"{{{NS}}}version")
    ver_el.set("ver", version)
    ver_el.set("rel", release)
    ver_el.set("epoch", epoch)
    arch_el = ET.SubElement(pkg, f"{{{NS}}}arch")
    arch_el.text = arch
    checksum_el = ET.SubElement(pkg, f"{{{NS}}}checksum")
    checksum_el.set("type", "sha256")
    checksum_el.text = "abc123"
    fmt = ET.SubElement(pkg, f"{{{NS}}}format")
    src = ET.SubElement(fmt, f"{{{RPM_NS}}}sourcerpm")
    src.text = f"{name}-{version}-{release}.src.rpm"
    return pkg


def _make_advisory(name, nevra_list):
    """Build a mock RedHatAdvisory with packages."""
    advisory = Mock()
    advisory.name = name
    advisory.id = 1
    pkgs = []
    for nevra in nevra_list:
        pkg = Mock()
        pkg.nevra = nevra
        pkgs.append(pkg)
    advisory.packages = pkgs
    advisory.cves = []
    advisory.bugzilla_tickets = []
    advisory.synopsis = "Test advisory"
    advisory.description = "Test description"
    advisory.kind = "SECURITY"
    advisory.severity = "Important"
    advisory.topic = "Test topic"
    return advisory


def _make_mirror(mirror_id=1, name="Rocky Linux 9 x86_64"):
    mirror = Mock()
    mirror.id = mirror_id
    mirror.name = name
    mirror.match_arch = "x86_64"
    mirror.match_major_version = 9
    mirror.match_minor_version = 7
    mirror.match_variant = "BaseOS"
    mirror.supported_product_id = 1
    return mirror


def _make_rpm_repomd():
    rpm_repomd = Mock()
    rpm_repomd.url = "https://example.com/BaseOS/x86_64/os/repodata/repomd.xml"
    rpm_repomd.debug_url = "https://example.com/BaseOS/x86_64/debug/repodata/repomd.xml"
    rpm_repomd.source_url = "https://example.com/BaseOS/source/repodata/repomd.xml"
    rpm_repomd.repo_name = "baseos"
    rpm_repomd.arch = "x86_64"
    rpm_repomd.production = True
    return rpm_repomd


def _mock_repomd_downloads(repo_pkgs):
    """
    Create patches for repomd.download_xml and repomd.get_data_from_repomd.

    repo_pkgs: list of ET.Element package elements to return from primary XML.
    """
    primary_xml = ET.Element(f"{{{NS}}}metadata")
    for pkg in repo_pkgs:
        primary_xml.append(pkg)

    async def fake_download_xml(url, **kwargs):
        return ET.Element("repomd")

    async def fake_get_data(url, data_type, el, is_yaml=False):
        if data_type == "primary":
            return primary_xml
        return None

    return fake_download_xml, fake_get_data


class TestPackageNameExtraction(unittest.TestCase):
    """Test package_name extraction from source RPMs"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_advisory_nvra = "libarchive-3.3.3-5.el8.src.rpm"
        self.test_binary_nvra = "libarchive-0:3.3.3-5.el8.x86_64.rpm"
        self.test_debuginfo_nvra = (
            "libarchive-debuginfo-0:3.3.3-5.el8.aarch64.rpm"
        )

    def test_nvra_regex_matches_source_rpm(self):
        """Test NVRA_RE regex matches source RPM correctly"""
        match = repomd.NVRA_RE.search(self.test_advisory_nvra)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "libarchive")

    def test_nvra_regex_matches_binary_rpm(self):
        """Test NVRA_RE regex matches binary RPM name"""
        source_rpm_text = "libarchive-3.3.3-5.el8.src.rpm"
        match = repomd.NVRA_RE.search(source_rpm_text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "libarchive")

    def test_nvra_regex_handles_module_packages(self):
        """Test NVRA_RE regex extracts package name from module packages"""
        module_source_rpm = (
            "postgresql-12.5-1.module+el8.3.0+6656+95b1e5d5.src.rpm"
        )
        match = repomd.NVRA_RE.search(module_source_rpm)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "postgresql")

    def test_nvra_regex_no_match_returns_none(self):
        """Test NVRA_RE regex returns None for invalid format"""
        invalid_nvra = "not-a-valid-package-name"
        match = repomd.NVRA_RE.search(invalid_nvra)
        self.assertIsNone(match)

    def test_source_rpm_element_handling(self):
        """Test handling of missing source_rpm XML element"""
        xml_with_sourcerpm = """
        <package xmlns:rpm="http://linux.duke.edu/metadata/rpm">
            <format>
                <rpm:sourcerpm>libarchive-3.3.3-5.el8.src.rpm</rpm:sourcerpm>
            </format>
        </package>
        """
        xml_without_sourcerpm = """
        <package xmlns:rpm="http://linux.duke.edu/metadata/rpm">
            <format>
            </format>
        </package>
        """

        root_with = ET.fromstring(xml_with_sourcerpm)
        source_rpm_with = root_with.find("format").find(
            "{http://linux.duke.edu/metadata/rpm}sourcerpm"
        )
        self.assertIsNotNone(source_rpm_with)

        root_without = ET.fromstring(xml_without_sourcerpm)
        source_rpm_without = root_without.find("format").find(
            "{http://linux.duke.edu/metadata/rpm}sourcerpm"
        )
        self.assertIsNone(source_rpm_without)

    def test_package_name_extraction_workflow(self):
        """Test complete workflow of package_name extraction"""
        test_cases = [
            {
                "name": "Valid source RPM",
                "advisory_nvra": "libarchive-3.3.3-5.el8.src.rpm",
                "is_source": True,
                "source_rpm_text": None,
                "expected": "libarchive",
            },
            {
                "name": "Valid binary RPM with source",
                "advisory_nvra": "libarchive-0:3.3.3-5.el8.x86_64",
                "is_source": False,
                "source_rpm_text": "libarchive-3.3.3-5.el8.src.rpm",
                "expected": "libarchive",
            },
            {
                "name": "Binary RPM with missing source",
                "advisory_nvra": (
                    "libarchive-debuginfo-0:3.3.3-5.el8.aarch64"
                ),
                "is_source": False,
                "source_rpm_text": None,
                "expected": None,
            },
            {
                "name": "Invalid source RPM format",
                "advisory_nvra": "invalid-format",
                "is_source": True,
                "source_rpm_text": None,
                "expected": None,
            },
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case["name"]):
                advisory_nvra = test_case["advisory_nvra"]
                source_rpm_text = test_case["source_rpm_text"]
                expected = test_case["expected"]

                package_name = None

                if advisory_nvra.endswith(
                    ".src.rpm"
                ) or advisory_nvra.endswith(".src"):
                    source_nvra = repomd.NVRA_RE.search(advisory_nvra)
                    if source_nvra:
                        package_name = source_nvra.group(1)
                elif source_rpm_text:
                    source_nvra = repomd.NVRA_RE.search(source_rpm_text)
                    if source_nvra:
                        package_name = source_nvra.group(1)

                self.assertEqual(
                    package_name,
                    expected,
                    f"Failed for {test_case['name']}: "
                    f"expected {expected}, got {package_name}",
                )


class TestProcessRepomdMatching(unittest.TestCase):
    """Test the NVRA matching logic in process_repomd."""

    def setUp(self):
        self._logger_patcher = patch(
            "apollo.rpmworker.rh_matcher_activities.Logger"
        )
        self._logger_patcher.start()

    def tearDown(self):
        self._logger_patcher.stop()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_exact_match(self):
        """Packages with identical release strings match directly."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0001",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0001", result)

    def test_prefix_match_rocky_suffix(self):
        """Rocky packages with .rocky.X.Y suffix match via prefix."""
        repo_pkgs = [
            _make_pkg_element(
                "openssh", "8.7p1", "49.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0002",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0002", result)

    def test_no_match(self):
        """Advisory packages not in repo produce no match."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0003",
            ["curl-0:7.76.1-29.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0003", result)

    def test_module_package_match(self):
        """Module packages with module+ in release match directly."""
        repo_pkgs = [
            _make_pkg_element(
                "postgresql",
                "12.5",
                "1.module+el9.3.0+6656+95b1e5d5",
                "x86_64",
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0004",
            ["postgresql-0:12.5-1.module+el9.3.0+6656+95b1e5d5.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0004", result)

    def test_module_cleaned_key_keeps_lowest_evr(self):
        """el8.5 and el8.10 share a cleaned module NVR; keep the older rebuild."""
        repo_pkgs = [
            _make_pkg_element(
                "python2-attrs",
                "17.4.0",
                "10.module+el8.10.0+40170+3b32c808",
                "noarch",
            ),
            _make_pkg_element(
                "python2-attrs",
                "17.4.0",
                "10.module+el8.5.0+706+e497ead8",
                "noarch",
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2019:0981",
            [
                "python2-attrs-0:17.4.0-10.module+el8.0.0+2961+596d0223.noarch.rpm",
            ],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2019:0981", result)
        pkgs = result["RHSA-2019:0981"]["packages"][0]
        rels = {pkg.find(f"{{{NS}}}version").attrib["rel"] for pkg in pkgs}
        self.assertEqual(rels, {"10.module+el8.5.0+706+e497ead8"})

    def test_arch_mismatch_no_match(self):
        """Packages with wrong arch don't match."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "aarch64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0005",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0005", result)

    def test_prefix_match_version_mismatch_no_match(self):
        """Older Rocky EVR than RH fixed must not match (prefix or EVR)."""
        repo_pkgs = [
            _make_pkg_element(
                "openssh", "8.7p1", "48.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0006",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0006", result)

    def test_evr_match_newer_rocky_release(self):
        """Rocky already shipping a newer release than RH fixed still matches."""
        repo_pkgs = [
            _make_pkg_element(
                "openssh", "8.7p1", "50.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0010",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0010", result)

    def test_evr_match_different_release_string(self):
        """RH 7.el9_2.1 vs Rocky 8.el9 (no shared NVR prefix) still matches."""
        repo_pkgs = [
            _make_pkg_element("dbus", "1.12.20", "8.el9", "x86_64", epoch="1"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0011",
            ["dbus-1:1.12.20-7.el9_2.1.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0011", result)

    def test_evr_match_picks_lowest_satisfying(self):
        """When multiple newer Rocky builds exist, still match the advisory."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "6.el9", "x86_64"),
            _make_pkg_element("bash", "5.1.8", "10.el9", "x86_64"),
            _make_pkg_element("bash", "5.1.8", "9.el9", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0012",
            ["bash-0:5.1.8-8.el9.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0012", result)

    def test_multiple_advisories_independent_matching(self):
        """Each advisory matches independently against repo packages."""
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
            _make_pkg_element(
                "openssh", "8.7p1", "49.el9_7.rocky.0.1", "x86_64"
            ),
        ]
        advisory_match = _make_advisory(
            "RHSA-2026:0007",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        advisory_no_match = _make_advisory(
            "RHSA-2026:0008",
            ["curl-0:7.76.1-29.el9_7.x86_64.rpm"],
        )
        advisory_prefix = _make_advisory(
            "RHSA-2026:0009",
            ["openssh-0:8.7p1-49.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        advisories = [advisory_match, advisory_no_match, advisory_prefix]
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(
                    _make_mirror(), _make_rpm_repomd(), advisories
                )
            )
        self.assertIn("RHSA-2026:0007", result)
        self.assertNotIn("RHSA-2026:0008", result)
        self.assertIn("RHSA-2026:0009", result)


class TestModularFieldResolution(unittest.TestCase):
    """distro-tools#72: RH CSAF module fallback when modules.yaml misses Rocky NEVRA."""

    def test_rh_csaf_fallback_when_yaml_misses(self):
        from apollo.rpmworker.rh_matcher_activities import _resolve_modular_package_fields

        rocky_nevra = "nodejs-1:16.20.2-4.module+el8.9.0+1760+903d54b9.x86_64.rpm"
        cleaned_rh = "module.nodejs-1:16.20.2-4.el8.9.0.x86_64"
        module_pkgs = {}
        rh_modules = {
            cleaned_rh: {
                "module_name": "nodejs",
                "module_stream": "16",
                "module_version": "8060020220913080029",
                "module_context": "d63f516d",
            }
        }
        name, stream, version, context = _resolve_modular_package_fields(
            "4.module+el8.9.0+1760+903d54b9",
            rocky_nevra,
            cleaned_rh,
            module_pkgs,
            rh_modules,
        )
        self.assertEqual(name, "nodejs")
        self.assertEqual(stream, "16")
        self.assertEqual(version, "8060020220913080029")
        self.assertEqual(context, "d63f516d")

    def test_yaml_lookup_normalizes_rocky_suffix(self):
        from apollo.rpmworker.rh_matcher_activities import _resolve_modular_package_fields

        rocky_nevra = (
            "ocaml-libguestfs-1:1.44.0-5.module+el8.6.0+1052+ff61d164.rocky.aarch64.rpm"
        )
        yaml_key = "ocaml-libguestfs-1:1.44.0-5.module+el8.6.0+1052+ff61d164.aarch64"
        module_pkgs = {
            yaml_key: ("virt-devel", "rhel", "8060020220913080029", "d63f516d"),
        }
        name, stream, version, context = _resolve_modular_package_fields(
            "5.module+el8.6.0+1052+ff61d164.rocky",
            rocky_nevra,
            "module.ocaml-libguestfs-1:1.44.0-5.el8.6.0.aarch64",
            module_pkgs,
            {},
        )
        self.assertEqual(name, "virt-devel")
        self.assertEqual(stream, "rhel")


class TestStreamProductName(unittest.TestCase):
    """packages.product_name must match affected_products.name on the major stream."""

    def test_collapses_point_release_in_mirror_name(self):
        mirror = _make_mirror(name="Rocky Linux 9.6 aarch64")
        mirror.match_arch = "aarch64"
        mirror.match_minor_version = 6
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 9 aarch64")

    def test_stream_mirror_name_unchanged(self):
        mirror = _make_mirror(name="Rocky Linux 9 x86_64")
        mirror.match_minor_version = None
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 9 x86_64")

    def test_riscv64_name_without_minor_unchanged(self):
        mirror = _make_mirror(name="Rocky Linux 10 riscv64")
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        mirror.match_arch = "x86_64"
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 10 riscv64")
        self.assertEqual(repo_arch_for_mirror(mirror), "riscv64")

    def test_repo_arch_follows_name_not_match_arch(self):
        mirror = _make_mirror(name="Rocky Linux 10 x86_64")
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        self.assertEqual(repo_arch_for_mirror(mirror), "x86_64")

    def test_vault_riscv64_repo_arch(self):
        mirror = _make_mirror(name="Rocky Linux 10 riscv64 [vault 10.0]")
        mirror.match_major_version = 10
        mirror.match_minor_version = 0
        mirror.match_arch = "x86_64"
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 10 riscv64")
        self.assertEqual(repo_arch_for_mirror(mirror), "riscv64")

    def test_zero_minor_collapsed(self):
        mirror = _make_mirror(name="Rocky Linux 10.0 riscv64")
        mirror.match_major_version = 10
        mirror.match_minor_version = 0
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 10 riscv64")

    def test_vault_suffix_stripped_before_label(self):
        mirror = _make_mirror(name="Rocky Linux 10 x86_64 [vault 10.0]")
        mirror.match_major_version = 10
        mirror.match_minor_version = 0
        self.assertEqual(stream_product_name(mirror), "Rocky Linux 10 x86_64")
        self.assertTrue(_is_historical_mirror(mirror))

    def test_stream_mirror_is_not_historical(self):
        self.assertFalse(_is_historical_mirror(_make_mirror()))


class TestAdvisoryClonePublishedAt(unittest.TestCase):
    def test_prefers_red_hat_issued_at(self):
        advisory = Mock()
        advisory.red_hat_issued_at = datetime.datetime(2025, 10, 3, 19, 56, 45)
        fallback = datetime.datetime(2026, 8, 28, 20, 0, 0)
        self.assertEqual(
            advisory_clone_published_at(advisory, fallback),
            advisory.red_hat_issued_at,
        )

    def test_falls_back_when_issued_missing(self):
        advisory = Mock()
        advisory.red_hat_issued_at = None
        fallback = datetime.datetime(2026, 8, 28, 20, 0, 0)
        self.assertEqual(advisory_clone_published_at(advisory, fallback), fallback)


def _new_pkg(nevra, product_name="Rocky Linux 10 x86_64"):
    return NewPackage(
        nevra=nevra,
        checksum="abc",
        checksum_type="sha256",
        module_context=None,
        module_name=None,
        module_stream=None,
        module_version=None,
        repo_name="AppStream",
        package_name="firefox",
        mirror_id=1,
        supported_product_id=1,
        product_name=product_name,
    )


class TestCreateOrUpdateAdvisoryPackages(unittest.TestCase):
    def setUp(self):
        self._logger_patcher = patch(
            "apollo.rpmworker.rh_matcher_activities.Logger"
        )
        self._logger_patcher.start()

    def tearDown(self):
        self._logger_patcher.stop()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_rematch_does_not_replace_existing_nevras(self):
        existing = Mock(
            id=1,
            nevra="firefox-0:128.12.0-1.el10_0.x86_64.rpm",
            product_name="Rocky Linux 10 x86_64",
            module_name=None,
        )
        filter_mock = MagicMock()
        filter_mock.all = AsyncMock(return_value=[existing])
        filter_mock.update = AsyncMock()
        filter_mock.delete = AsyncMock()
        advisory = Mock(id=10, name="RLSA-2025:10073")
        newer = _new_pkg("firefox-0:140.10.2-1.el10_2.x86_64.rpm")
        with patch(
            "apollo.rpmworker.rh_matcher_activities.AdvisoryPackage"
        ) as AP:
            AP.filter.return_value = filter_mock
            AP.bulk_create = AsyncMock()
            self._run(
                create_or_update_advisory_packages(
                    advisory, [newer], update_advisory=True
                )
            )
            AP.bulk_create.assert_not_called()
            filter_mock.delete.assert_not_called()

    def test_repair_replaces_nevras(self):
        existing = Mock(
            id=1,
            nevra="firefox-0:140.10.2-1.el10_2.x86_64.rpm",
            product_name="Rocky Linux 10 x86_64",
            module_name=None,
        )
        filter_mock = MagicMock()
        filter_mock.all = AsyncMock(return_value=[existing])
        filter_mock.update = AsyncMock()
        filter_mock.delete = AsyncMock()
        advisory = Mock(id=10, name="RLSA-2025:10073")
        shipped = _new_pkg("firefox-0:128.12.0-1.el10_0.x86_64.rpm")
        with patch(
            "apollo.rpmworker.rh_matcher_activities.AdvisoryPackage"
        ) as AP:
            AP.filter.return_value = filter_mock
            AP.bulk_create = AsyncMock()
            self._run(
                create_or_update_advisory_packages(
                    advisory,
                    [shipped],
                    update_advisory=True,
                    replace_packages=True,
                )
            )
            AP.bulk_create.assert_called_once()
            filter_mock.delete.assert_called_once()

    def test_repair_keeps_packages_for_arches_not_in_new_set(self):
        existing_x86 = Mock(
            id=1,
            nevra="glibc-0:2.28-251.el8_10.x86_64.rpm",
            product_name="Rocky Linux 8 x86_64",
            module_name=None,
        )
        existing_arm = Mock(
            id=2,
            nevra="glibc-0:2.28-251.el8_10.aarch64.rpm",
            product_name="Rocky Linux 8 aarch64",
            module_name=None,
        )
        filter_mock = MagicMock()
        filter_mock.all = AsyncMock(return_value=[existing_x86, existing_arm])
        filter_mock.update = AsyncMock()
        filter_mock.delete = AsyncMock()
        advisory = Mock(id=10, name="RLSA-2026:2786")
        shipped = _new_pkg(
            "glibc-0:2.28-251.el8_10.2.x86_64.rpm",
            product_name="Rocky Linux 8 x86_64",
        )
        with patch(
            "apollo.rpmworker.rh_matcher_activities.AdvisoryPackage"
        ) as AP:
            AP.filter.return_value = filter_mock
            AP.bulk_create = AsyncMock()
            self._run(
                create_or_update_advisory_packages(
                    advisory,
                    [shipped],
                    update_advisory=True,
                    replace_packages=True,
                )
            )
            AP.bulk_create.assert_called_once()
            filter_mock.delete.assert_called_once()
            deleted = None
            for call in AP.filter.call_args_list:
                kwargs = call.kwargs
                if "nevra__in" in kwargs:
                    deleted = set(kwargs["nevra__in"])
            self.assertEqual(
                deleted, {"glibc-0:2.28-251.el8_10.x86_64.rpm"}
            )


class TestProcessRepomdSkippedUrls(unittest.TestCase):
    def setUp(self):
        self._logger_patcher = patch(
            "apollo.rpmworker.rh_matcher_activities.Logger"
        )
        self._logger_patcher.start()

    def tearDown(self):
        self._logger_patcher.stop()

    def _run(self, coro):
        return asyncio.run(coro)

    def test_debug_url_404_does_not_abort_os_match(self):
        repo_pkgs = [_make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64")]
        advisory = _make_advisory(
            "RHSA-2026:0001",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)

        async def download_or_fail(url, **kwargs):
            if "debug" in url:
                raise Exception(f"Failed to get {url}: 404")
            return await fake_dl(url, **kwargs)

        with patch.object(repomd, "download_xml", side_effect=download_or_fail), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0001", result)

    def test_firefox_picks_el10_0_when_both_in_index(self):
        repo_pkgs = [
            _make_pkg_element("firefox", "128.12.0", "1.el10_0", "x86_64"),
            _make_pkg_element("firefox", "140.10.2", "1.el10_2", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2025:10073",
            ["firefox-0:128.12.0-1.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2025:10073", result)

    def test_firefox_el10_2_alone_does_not_match_el10_0_rhsa(self):
        """Current AppStream HEAD must not clone an el10_0 RHSA."""
        repo_pkgs = [
            _make_pkg_element("firefox", "140.10.2", "1.el10_2", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2025:10073",
            ["firefox-0:128.12.0-1.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2025:10073", result)

    def test_kernel_el10_2_alone_does_not_match_el10_0_rhsa(self):
        """Current kernel 211.el10_2 must not clone RHSA kernel 55.el10_0."""
        repo_pkgs = [
            _make_pkg_element("kernel", "6.12.0", "211.16.1.el10_2.0.1", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2025:9348",
            ["kernel-0:6.12.0-55.18.1.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2025:9348", result)

    def test_firefox_el8_same_nvr_does_not_match_el10_rhsa(self):
        """Cleaned NVR is identical; dist major must still differ."""
        repo_pkgs = [
            _make_pkg_element("firefox", "128.12.0", "1.el8_10", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2025:10073",
            ["firefox-0:128.12.0-1.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2025:10073", result)

    def test_firefox_mixed_majors_only_el10_matches(self):
        repo_pkgs = [
            _make_pkg_element("firefox", "128.12.0", "1.el8_10", "x86_64"),
            _make_pkg_element("firefox", "128.12.0", "1.el9_6", "x86_64"),
            _make_pkg_element("firefox", "128.12.0", "1.el10_0", "x86_64"),
        ]
        advisory = _make_advisory(
            "RHSA-2025:10073",
            ["firefox-0:128.12.0-1.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2025:10073", result)
        pkgs = result["RHSA-2025:10073"]["packages"][0]
        releases = sorted(
            pkg.find(f"{{{NS}}}version").attrib["rel"] for pkg in pkgs
        )
        self.assertEqual(releases, ["1.el10_0"])

    def test_openssl_el8_6_rhsa_matches_el8_10_rebuild(self):
        """Production RLSA-2024:7848 is 1.1.1k-14.el8_10 for an el8_6 RHSA."""
        repo_pkgs = [
            _make_pkg_element(
                "openssl-libs", "1.1.1k", "14.el8_10", "x86_64", epoch="1"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2024:7848",
            ["openssl-libs-1:1.1.1k-14.el8_6.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2024:7848", result)

    def test_openssl_el9_does_not_match_el8_rhsa(self):
        """Vault EL9 openssl 3.x must not clone an EL8 1.1.1k RHSA."""
        repo_pkgs = [
            _make_pkg_element(
                "openssl-libs", "3.0.1", "43.el9_0", "x86_64", epoch="1"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2024:7848",
            ["openssl-libs-1:1.1.1k-14.el8_10.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(_make_mirror(), _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2024:7848", result)

    def test_matched_packages_are_isolated_per_advisory(self):
        repo_pkgs = [
            _make_pkg_element("bash", "5.1.8", "9.el9_7", "x86_64"),
            _make_pkg_element("firefox", "128.12.0", "1.el9_6", "x86_64"),
        ]
        bash = _make_advisory(
            "RHSA-2026:0001",
            ["bash-0:5.1.8-9.el9_7.x86_64.rpm"],
        )
        firefox = _make_advisory(
            "RHSA-2025:10072",
            ["firefox-0:128.12.0-1.el9_6.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(
                    _make_mirror(), _make_rpm_repomd(), [bash, firefox]
                )
            )
        bash_names = {
            pkg.find(f"{{{NS}}}name").text
            for pkg in result["RHSA-2026:0001"]["packages"][0]
        }
        ff_names = {
            pkg.find(f"{{{NS}}}name").text
            for pkg in result["RHSA-2025:10072"]["packages"][0]
        }
        self.assertEqual(bash_names, {"bash"})
        self.assertEqual(ff_names, {"firefox"})

    def test_x86_64_rhsa_matches_riscv64_repo(self):
        """RHEL has no riscv64 product; donor x86_64 RH NEVRAs clone .riscv64."""
        mirror = _make_mirror(mirror_id=2, name="Rocky Linux 10 riscv64")
        mirror.match_arch = "x86_64"
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        repo_pkgs = [
            _make_pkg_element("bash", "5.2.26", "6.el10_0", "riscv64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0001",
            ["bash-0:5.2.26-6.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(mirror, _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0001", result)
        arches = {
            pkg.find(f"{{{NS}}}arch").text
            for pkg in result["RHSA-2026:0001"]["packages"][0]
        }
        self.assertEqual(arches, {"riscv64"})

    def test_x86_64_rhsa_matches_riscv64_rocky_suffix(self):
        mirror = _make_mirror(mirror_id=2, name="Rocky Linux 10 riscv64")
        mirror.match_arch = "x86_64"
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        repo_pkgs = [
            _make_pkg_element(
                "openssh", "9.9p1", "7.el10_0.rocky.0.1", "riscv64"
            ),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0002",
            ["openssh-0:9.9p1-7.el10_0.x86_64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(mirror, _make_rpm_repomd(), [advisory])
            )
        self.assertIn("RHSA-2026:0002", result)

    def test_aarch64_rhsa_does_not_rewrite_onto_riscv64(self):
        mirror = _make_mirror(mirror_id=2, name="Rocky Linux 10 riscv64")
        mirror.match_arch = "x86_64"
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        repo_pkgs = [
            _make_pkg_element("bash", "5.2.26", "6.el10_0", "riscv64"),
        ]
        advisory = _make_advisory(
            "RHSA-2026:0001",
            ["bash-0:5.2.26-6.el10_0.aarch64.rpm"],
        )
        fake_dl, fake_data = _mock_repomd_downloads(repo_pkgs)
        with patch.object(repomd, "download_xml", side_effect=fake_dl), \
             patch.object(repomd, "get_data_from_repomd", side_effect=fake_data):
            result = self._run(
                process_repomd(mirror, _make_rpm_repomd(), [advisory])
            )
        self.assertNotIn("RHSA-2026:0001", result)


class TestRepoArchHelpers(unittest.TestCase):
    def test_nvra_with_arch_rewrites_cleaned_and_rpm(self):
        self.assertEqual(
            _nvra_with_arch("bash-5.2.26-6.x86_64", "riscv64"),
            "bash-5.2.26-6.riscv64",
        )
        self.assertEqual(
            _nvra_with_arch("bash-0:5.2.26-6.el10_0.x86_64.rpm", "riscv64"),
            "bash-0:5.2.26-6.el10_0.riscv64.rpm",
        )
        self.assertEqual(
            _nvra_with_arch("module.bash-5.2.26-6.x86_64", "riscv64"),
            "module.bash-5.2.26-6.riscv64",
        )

    def test_repo_search_cleaned_rewrites_donor_only(self):
        mirror = _make_mirror(name="Rocky Linux 10 riscv64")
        mirror.match_arch = "x86_64"
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        self.assertEqual(
            _repo_search_cleaned(mirror, "bash-5.2.26-6.x86_64", "x86_64"),
            "bash-5.2.26-6.riscv64",
        )
        self.assertEqual(
            _repo_search_cleaned(mirror, "bash-5.2.26-6.noarch", "noarch"),
            "bash-5.2.26-6.noarch",
        )
        x86 = _make_mirror(name="Rocky Linux 10 x86_64")
        x86.match_major_version = 10
        x86.match_minor_version = None
        self.assertEqual(
            _repo_search_cleaned(x86, "bash-5.2.26-6.x86_64", "x86_64"),
            "bash-5.2.26-6.x86_64",
        )

    def test_repomd_belongs_accepts_lied_stored_arch(self):
        mirror = _make_mirror(name="Rocky Linux 10 riscv64")
        mirror.match_arch = "x86_64"
        mirror.match_major_version = 10
        mirror.match_minor_version = None
        lied = _make_rpm_repomd()
        lied.arch = "x86_64"
        lied.url = (
            "https://dl.rockylinux.org/pub/rocky/10/BaseOS/riscv64/"
            "os/repodata/repomd.xml"
        )
        self.assertTrue(_repomd_belongs_to_mirror(mirror, lied))
        truthful = _make_rpm_repomd()
        truthful.arch = "riscv64"
        truthful.url = lied.url
        self.assertTrue(_repomd_belongs_to_mirror(mirror, truthful))

    def test_repomd_belongs_rejects_other_arch_row(self):
        mirror = _make_mirror(name="Rocky Linux 9 x86_64")
        other = _make_rpm_repomd()
        other.arch = "aarch64"
        other.url = (
            "https://dl.rockylinux.org/pub/rocky/9/BaseOS/aarch64/"
            "os/repodata/repomd.xml"
        )
        self.assertFalse(_repomd_belongs_to_mirror(mirror, other))


class TestAffectedProductRowsFromPackages(unittest.TestCase):
    def test_rows_follow_cloned_nevras_not_walked_majors(self):
        pkgs = [
            _new_pkg(
                "openssl-libs-1:1.1.1k-14.el8_10.x86_64.rpm",
                product_name="Rocky Linux 8 x86_64",
            ),
            _new_pkg(
                "openssl-libs-1:1.1.1k-14.el8_10.aarch64.rpm",
                product_name="Rocky Linux 8 aarch64",
            ),
        ]
        rows = affected_product_rows_from_packages(10, "Rocky Linux", pkgs)
        majors = sorted({row["major_version"] for row in rows})
        names = sorted({row["name"] for row in rows})
        self.assertEqual(majors, [8])
        self.assertEqual(names, ["Rocky Linux 8 aarch64", "Rocky Linux 8 x86_64"])
        self.assertTrue(all(row["minor_version"] is None for row in rows))

    def test_empty_product_name_synthesizes_stream_label(self):
        pkgs = [
            _new_pkg(
                "openssl-libs-1:3.2.2-6.el9_5.x86_64.rpm",
                product_name="",
            ),
        ]
        rows = affected_product_rows_from_packages(11, "Rocky Linux", pkgs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Rocky Linux 9 x86_64")
        self.assertEqual(rows[0]["major_version"], 9)
        self.assertEqual(rows[0]["arch"], "x86_64")

    def test_stale_walk_product_name_does_not_widen_major(self):
        pkgs = [
            _new_pkg(
                "nodejs-1:12.18.4-2.module+el8.3.0+101.x86_64.rpm",
                product_name="Rocky Linux 9 x86_64",
            ),
        ]
        rows = affected_product_rows_from_packages(12, "Rocky Linux", pkgs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["major_version"], 8)
        self.assertEqual(rows[0]["name"], "Rocky Linux 8 x86_64")

    def test_src_does_not_create_src_product_when_binaries_exist(self):
        pkgs = [
            _new_pkg(
                "firefox-0:128.12.0-1.el10_0.x86_64.rpm",
                product_name="Rocky Linux 10 x86_64",
            ),
            _new_pkg(
                "firefox-0:128.12.0-1.el10_0.src.rpm",
                product_name="Rocky Linux 10 x86_64",
            ),
        ]
        rows = affected_product_rows_from_packages(13, "Rocky Linux", pkgs)
        arches = sorted({row["arch"] for row in rows})
        names = sorted({row["name"] for row in rows})
        self.assertEqual(arches, ["x86_64"])
        self.assertEqual(names, ["Rocky Linux 10 x86_64"])

    def test_src_only_falls_back_to_x86_64(self):
        pkgs = [
            _new_pkg(
                "firefox-0:128.12.0-1.el10_0.src.rpm",
                product_name="Rocky Linux 10 x86_64",
            ),
        ]
        rows = affected_product_rows_from_packages(14, "Rocky Linux", pkgs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arch"], "x86_64")
        self.assertEqual(rows[0]["name"], "Rocky Linux 10 x86_64")

    def test_src_only_riscv64_uses_stream_arch(self):
        pkgs = [
            _new_pkg(
                "firefox-0:128.12.0-1.el10_0.src.rpm",
                product_name="Rocky Linux 10 riscv64",
            ),
        ]
        rows = affected_product_rows_from_packages(16, "Rocky Linux", pkgs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arch"], "riscv64")
        self.assertEqual(rows[0]["name"], "Rocky Linux 10 riscv64")

    def test_riscv64_binary_stamps_riscv64_arch(self):
        pkgs = [
            _new_pkg(
                "bash-0:5.2.26-6.el10_0.riscv64.rpm",
                product_name="Rocky Linux 10 riscv64",
            ),
        ]
        rows = affected_product_rows_from_packages(17, "Rocky Linux", pkgs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arch"], "riscv64")
        self.assertEqual(rows[0]["name"], "Rocky Linux 10 riscv64")

    def test_noarch_uses_stream_label_arch(self):
        pkgs = [
            _new_pkg(
                "tzdata-0:2025a-1.el10_0.noarch.rpm",
                product_name="Rocky Linux 10 aarch64",
            ),
        ]
        rows = affected_product_rows_from_packages(15, "Rocky Linux", pkgs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arch"], "aarch64")
        self.assertEqual(rows[0]["name"], "Rocky Linux 10 aarch64")


class TestRhAdvisoryMatchesMajor(unittest.TestCase):
    def test_affected_product_major_wins(self):
        advisory = _make_advisory(
            "RHSA-2025:10073",
            ["firefox-0:128.12.0-1.el10_0.x86_64.rpm"],
        )
        product = Mock()
        product.major_version = 10
        advisory.affected_products = [product]
        self.assertTrue(rh_advisory_matches_major(advisory, 10))
        self.assertFalse(rh_advisory_matches_major(advisory, 8))

    def test_package_dist_when_no_affected_products(self):
        advisory = _make_advisory(
            "RHSA-2025:10073",
            ["firefox-0:128.12.0-1.el10_0.x86_64.rpm"],
        )
        advisory.affected_products = []
        self.assertTrue(rh_advisory_matches_major(advisory, 10))
        self.assertFalse(rh_advisory_matches_major(advisory, 8))


if __name__ == "__main__":
    unittest.main()

