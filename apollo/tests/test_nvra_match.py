"""Unit tests for NVRA alias matching (prefix + EVR >=)."""

import unittest
from xml.etree import ElementTree as ET

from apollo.rpmworker.nvra_match import (
    find_nvra_alias,
    lowest_compatible_pkgs,
    pkg_dist_compatible_with_rh,
    select_clone_pkgs,
    _is_rebuild_prefix,
)

NS = "http://linux.duke.edu/metadata/common"


def _pkg(name, version, release, arch, epoch="0", mirror_id=None):
    pkg = ET.Element(f"{{{NS}}}package")
    ET.SubElement(pkg, f"{{{NS}}}name").text = name
    ver = ET.SubElement(pkg, f"{{{NS}}}version")
    ver.set("ver", version)
    ver.set("rel", release)
    ver.set("epoch", epoch)
    ET.SubElement(pkg, f"{{{NS}}}arch").text = arch
    if mirror_id is not None:
        pkg.set("mirror_id", str(mirror_id))
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

    def test_evr_does_not_cross_kernel_point_release(self):
        """RH el10_0 kernel 55 must not alias current-stream 211 on el10_2."""
        head = "kernel-6.12.0-211.16.1.x86_64"
        raw = {head: [_pkg("kernel", "6.12.0", "211.16.1.el10_2.0.1", "x86_64")]}
        alias = find_nvra_alias(
            "kernel-6.12.0-55.18.1.x86_64",
            [head],
            advisory_nevra="kernel-0:6.12.0-55.18.1.el10_0.x86_64.rpm",
            raw_pkg_nvras=raw,
        )
        self.assertIsNone(alias)

    def test_evr_does_not_cross_el9_7_to_el9_8(self):
        """RH el9_7 kernel 611 must not alias current el9_8 687."""
        head = "kernel-5.14.0-687.10.1.x86_64"
        raw = {head: [_pkg("kernel", "5.14.0", "687.10.1.el9_8.0.1", "x86_64")]}
        alias = find_nvra_alias(
            "kernel-5.14.0-611.41.1.x86_64",
            [head],
            advisory_nevra="kernel-0:5.14.0-611.41.1.el9_7.x86_64.rpm",
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


class TestLowestCompatiblePkgs(unittest.TestCase):
    def test_module_streams_keep_lowest_evr(self):
        """Cleaning strips module+el8.Y; keep vault el8.5 not current el8.10."""
        older = _pkg(
            "python2-attrs",
            "17.4.0",
            "10.module+el8.5.0+706+e497ead8",
            "noarch",
        )
        newer = _pkg(
            "python2-attrs",
            "17.4.0",
            "10.module+el8.10.0+40170+3b32c808",
            "noarch",
        )
        picked = lowest_compatible_pkgs(
            "python2-attrs-0:17.4.0-10.module+el8.0.0+2961+596d0223.noarch.rpm",
            [newer, older],
        )
        self.assertEqual(picked, [older])

    def test_openssl_el8_10_satisfies_el8_6(self):
        rocky = _pkg(
            "openssl-libs", "1.1.1k", "14.el8_10", "x86_64", epoch="1"
        )
        picked = lowest_compatible_pkgs(
            "openssl-libs-1:1.1.1k-14.el8_6.x86_64.rpm",
            [rocky],
        )
        self.assertEqual(picked, [rocky])

    def test_older_than_rh_skipped(self):
        older = _pkg("openssh", "8.7p1", "48.el9_7", "x86_64")
        picked = lowest_compatible_pkgs(
            "openssh-0:8.7p1-49.el9_7.x86_64.rpm",
            [older],
        )
        self.assertEqual(picked, [])

    def test_one_per_arch(self):
        x86 = _pkg(
            "python2-attrs",
            "17.4.0",
            "10.module+el8.5.0+706+e497ead8",
            "x86_64",
        )
        aarch = _pkg(
            "python2-attrs",
            "17.4.0",
            "10.module+el8.5.0+706+e497ead8",
            "aarch64",
        )
        newer_x86 = _pkg(
            "python2-attrs",
            "17.4.0",
            "10.module+el8.10.0+40170+3b32c808",
            "x86_64",
        )
        picked = lowest_compatible_pkgs(
            "python2-attrs-0:17.4.0-10.module+el8.0.0+2961+596d0223.x86_64.rpm",
            [newer_x86, x86, aarch],
        )
        rels = {
            (p.find(f"{{{NS}}}arch").text, p.find(f"{{{NS}}}version").attrib["rel"])
            for p in picked
        }
        self.assertEqual(
            rels,
            {
                ("x86_64", "10.module+el8.5.0+706+e497ead8"),
                ("aarch64", "10.module+el8.5.0+706+e497ead8"),
            },
        )


class TestSelectClonePkgs(unittest.TestCase):
    def test_prefers_current_stream_over_older_vault(self):
        """Yum repos have 48.rocky; vault 8.3 still has compose -31."""
        vault = _pkg(
            "platform-python", "3.6.8", "31.el8", "x86_64", mirror_id="vault"
        )
        current = _pkg(
            "platform-python",
            "3.6.8",
            "48.el8_7.rocky.0",
            "x86_64",
            mirror_id="cur",
        )
        picked = select_clone_pkgs(
            "platform-python-0:3.6.8-31.el8.x86_64.rpm",
            [vault, current],
            historical_mirror_ids={"vault"},
        )
        self.assertEqual(picked, [current])

    def test_vault_when_current_jumps_version(self):
        vault = _pkg(
            "firefox", "128.12.0", "1.el10_0", "x86_64", mirror_id="vault"
        )
        current = _pkg(
            "firefox", "140.10.2", "1.el10_2", "x86_64", mirror_id="cur"
        )
        picked = select_clone_pkgs(
            "firefox-0:128.12.0-1.el10_0.x86_64.rpm",
            [vault, current],
            historical_mirror_ids={"vault"},
        )
        self.assertEqual(picked, [vault])

    def test_vault_when_current_jumps_kernel_point_release(self):
        vault = _pkg(
            "kernel", "6.12.0", "55.18.1.el10_0", "x86_64", mirror_id="vault"
        )
        current = _pkg(
            "kernel", "6.12.0", "211.16.1.el10_2.0.1", "x86_64", mirror_id="cur"
        )
        picked = select_clone_pkgs(
            "kernel-0:6.12.0-55.18.1.el10_0.x86_64.rpm",
            [vault, current],
            historical_mirror_ids={"vault"},
        )
        self.assertEqual(picked, [vault])

    def test_openssl_14_not_replaced_by_current_17(self):
        vault = _pkg(
            "openssl-libs",
            "1.1.1k",
            "14.el8_10",
            "x86_64",
            epoch="1",
            mirror_id="vault",
        )
        current = _pkg(
            "openssl-libs",
            "1.1.1k",
            "17.el8_10",
            "x86_64",
            epoch="1",
            mirror_id="cur",
        )
        picked = select_clone_pkgs(
            "openssl-libs-1:1.1.1k-14.el8_6.x86_64.rpm",
            [vault, current],
            historical_mirror_ids={"vault"},
        )
        self.assertEqual(picked, [vault])


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
