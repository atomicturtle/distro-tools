"""Unit tests for NVRA alias matching (prefix + EVR >=)."""

import unittest
from xml.etree import ElementTree as ET

from apollo.rpmworker.nvra_match import (
    find_nvra_alias,
    pkg_dist_compatible_with_rh,
    _is_rebuild_prefix,
)

NS = "http://linux.duke.edu/metadata/common"


def _pkg(name, version, release, arch, epoch="0"):
    pkg = ET.Element(f"{{{NS}}}package")
    ET.SubElement(pkg, f"{{{NS}}}name").text = name
    ver = ET.SubElement(pkg, f"{{{NS}}}version")
    ver.set("ver", version)
    ver.set("rel", release)
    ver.set("epoch", epoch)
    ET.SubElement(pkg, f"{{{NS}}}arch").text = arch
    return pkg


class TestFindNvraAlias(unittest.TestCase):
    def test_prefix_preferred_over_evr(self):
        rocky = "openssh-8.7p1-49.rocky.0.1.x86_64"
        raw = {rocky: [_pkg("openssh", "8.7p1", "49.el9_7.rocky.0.1", "x86_64")]}
        alias = find_nvra_alias(
            "openssh-8.7p1-49.x86_64",
            [rocky, "openssh-8.7p1-50.x86_64"],
            advisory_nevra="openssh-0:8.7p1-49.el9_7.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, rocky)

    def test_prefix_requires_dot_boundary(self):
        """Release 80 must not prefix-match cleaned release 8."""
        self.assertFalse(_is_rebuild_prefix("openssh-8.7p1-80", "openssh-8.7p1-8"))
        self.assertTrue(
            _is_rebuild_prefix("openssh-8.7p1-8.rocky.0.1", "openssh-8.7p1-8")
        )
        # Without package XML, digit-extension must not alias via prefix.
        alias = find_nvra_alias(
            "openssh-8.7p1-8.x86_64",
            ["openssh-8.7p1-80.x86_64"],
            advisory_nevra="openssh-0:8.7p1-8.el9.x86_64.rpm",
            raw_pkg_nvras=None,
        )
        self.assertIsNone(alias)

    def test_digit_extension_can_still_evr_match(self):
        """After boundary reject, EVR >= may still select a newer release."""
        rocky = "openssh-8.7p1-80.x86_64"
        raw = {rocky: [_pkg("openssh", "8.7p1", "80.el9", "x86_64")]}
        alias = find_nvra_alias(
            "openssh-8.7p1-8.x86_64",
            [rocky],
            advisory_nevra="openssh-0:8.7p1-8.el9.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, rocky)

    def test_evr_picks_lowest_satisfying(self):
        older = "bash-5.1.8-6.x86_64"
        mid = "bash-5.1.8-9.x86_64"
        newer = "bash-5.1.8-10.x86_64"
        raw = {
            older: [_pkg("bash", "5.1.8", "6.el9", "x86_64")],
            mid: [_pkg("bash", "5.1.8", "9.el9", "x86_64")],
            newer: [_pkg("bash", "5.1.8", "10.el9", "x86_64")],
        }
        alias = find_nvra_alias(
            "bash-5.1.8-8.x86_64",
            [newer, older, mid],
            advisory_nevra="bash-0:5.1.8-8.el9.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, mid)

    def test_older_rocky_no_match(self):
        rocky = "openssh-8.7p1-48.rocky.0.1.x86_64"
        raw = {rocky: [_pkg("openssh", "8.7p1", "48.el9_7.rocky.0.1", "x86_64")]}
        alias = find_nvra_alias(
            "openssh-8.7p1-49.x86_64",
            [rocky],
            advisory_nevra="openssh-0:8.7p1-49.el9_7.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertIsNone(alias)

    def test_evr_does_not_cross_point_release(self):
        """RH el10_0 must not alias a later firefox *version* on el10_2."""
        head = "firefox-140.10.2-1.x86_64"
        raw = {head: [_pkg("firefox", "140.10.2", "1.el10_2", "x86_64")]}
        alias = find_nvra_alias(
            "firefox-128.12.0-1.x86_64",
            [head],
            advisory_nevra="firefox-0:128.12.0-1.el10_0.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertIsNone(alias)

    def test_evr_picks_same_point_release_not_later(self):
        shipped = "firefox-128.12.0-1.x86_64"
        head = "firefox-140.10.2-1.x86_64"
        raw = {
            shipped: [_pkg("firefox", "128.12.0", "1.el10_0", "x86_64")],
            head: [_pkg("firefox", "140.10.2", "1.el10_2", "x86_64")],
        }
        alias = find_nvra_alias(
            "firefox-128.12.0-1.x86_64",
            [head, shipped],
            advisory_nevra="firefox-0:128.12.0-1.el10_0.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, shipped)

    def test_unstamped_rocky_minor_still_evr_matches(self):
        """Rocky ``el9`` (no minor) may still satisfy RH ``el9_2``."""
        rocky = "dbus-1.12.20-8.x86_64"
        raw = {rocky: [_pkg("dbus", "1.12.20", "8.el9", "x86_64", epoch="1")]}
        alias = find_nvra_alias(
            "dbus-1.12.20-7.x86_64",
            [rocky],
            advisory_nevra="dbus-1:1.12.20-7.el9_2.1.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, rocky)

    def test_evr_aliases_later_rocky_point_release(self):
        """RH el8_6 openssl 1.1.1k-14 ships on Rocky as el8_10 (production)."""
        rocky = "openssl-libs-1.1.1k-14.x86_64"
        raw = {
            rocky: [_pkg("openssl-libs", "1.1.1k", "14.el8_10", "x86_64", epoch="1")]
        }
        alias = find_nvra_alias(
            "openssl-libs-1.1.1k-14.x86_64",
            [rocky],
            advisory_nevra="openssl-libs-1:1.1.1k-14.el8_6.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertEqual(alias, rocky)

    def test_evr_does_not_cross_upstream_version(self):
        """RH openssl 1.1.1k must not alias EL9 openssl 3.0.1."""
        el9 = "openssl-libs-3.0.1-43.x86_64"
        raw = {el9: [_pkg("openssl-libs", "3.0.1", "43.el9_0", "x86_64", epoch="1")]}
        alias = find_nvra_alias(
            "openssl-libs-1.1.1k-14.x86_64",
            [el9],
            advisory_nevra="openssl-libs-1:1.1.1k-14.el8_10.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertIsNone(alias)


class TestPkgDistCompatibleWithRh(unittest.TestCase):
    def test_el8_same_nvr_does_not_match_el10_rhsa(self):
        pkg = _pkg("firefox", "128.12.0", "1.el8_10", "x86_64")
        self.assertFalse(
            pkg_dist_compatible_with_rh(
                "firefox-0:128.12.0-1.el10_0.x86_64.rpm", pkg
            )
        )

    def test_el8_6_rhsa_matches_el8_10_rebuild(self):
        pkg = _pkg("openssl-libs", "1.1.1k", "14.el8_10", "x86_64", epoch="1")
        self.assertTrue(
            pkg_dist_compatible_with_rh(
                "openssl-libs-1:1.1.1k-14.el8_6.x86_64.rpm", pkg
            )
        )

    def test_el10_0_matches_el10_rhsa(self):
        pkg = _pkg("firefox", "128.12.0", "1.el10_0", "x86_64")
        self.assertTrue(
            pkg_dist_compatible_with_rh(
                "firefox-0:128.12.0-1.el10_0.x86_64.rpm", pkg
            )
        )

    def test_unstamped_el9_matches_el9_2(self):
        pkg = _pkg("dbus", "1.12.20", "8.el9", "x86_64", epoch="1")
        self.assertTrue(
            pkg_dist_compatible_with_rh(
                "dbus-1:1.12.20-7.el9_2.1.x86_64.rpm", pkg
            )
        )

    def test_find_alias_rejects_el8_for_el10_rhsa(self):
        """Cleaned NVR collision must not alias across majors."""
        el8 = "firefox-128.12.0-1.x86_64"
        raw = {el8: [_pkg("firefox", "128.12.0", "1.el8_10", "x86_64")]}
        alias = find_nvra_alias(
            el8,
            [el8],
            advisory_nevra="firefox-0:128.12.0-1.el10_0.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertIsNone(alias)


if __name__ == "__main__":
    unittest.main()
