"""Rocky Linux OVAL generator (one document per major version).

Emits OVAL 5.10 definitions keyed by RLSA, with RPM EVR criteria derived
from fixed advisory packages. Structure follows the common Rocky/RH OVAL
layout used by OpenSCAP consumers.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable, Optional
from xml.etree import ElementTree as ET

from apollo.exports import attribution
from apollo.exports.bulk import product_matches_major
from apollo.rpm_helpers import parse_nevra

OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
LINUX_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

GENERATOR_VERSION = "1.0.0"


def _qid(kind: str, seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
    return f"oval:org.rockylinux.{kind}:{digest}"


def build_oval_xml(advisories: Iterable, major: int) -> str:
    """Build an OVAL definitions document for Rocky Linux <major>."""
    ET.register_namespace("", OVAL_NS)
    ET.register_namespace("oval-def", OVAL_NS)
    ET.register_namespace("linux-def", LINUX_NS)
    ET.register_namespace("xsi", XSI_NS)

    root = ET.Element(
        f"{{{OVAL_NS}}}oval_definitions",
        {
            f"{{{XSI_NS}}}schemaLocation": (
                f"{OVAL_NS} "
                "https://oval.mitre.org/language/version5.10/"
                "ovaldefinition/complete/oval-definitions-schema.xsd"
            )
        },
    )

    generator = ET.SubElement(root, f"{{{OVAL_NS}}}generator")
    ET.SubElement(generator, f"{{{OVAL_NS}}}product_name").text = (
        "Rocky Linux Apollo OVAL Generator"
    )
    ET.SubElement(generator, f"{{{OVAL_NS}}}product_version").text = (
        GENERATOR_VERSION
    )
    ET.SubElement(generator, f"{{{OVAL_NS}}}schema_version").text = "5.10"
    ET.SubElement(generator, f"{{{OVAL_NS}}}timestamp").text = (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    )

    definitions = ET.SubElement(root, f"{{{OVAL_NS}}}definitions")
    tests = ET.SubElement(root, f"{{{OVAL_NS}}}tests")
    objects = ET.SubElement(root, f"{{{OVAL_NS}}}objects")
    states = ET.SubElement(root, f"{{{OVAL_NS}}}states")

    test_ids = set()
    object_ids = set()
    state_ids = set()

    for advisory in advisories:
        pkgs = []
        for pkg in advisory.packages or []:
            if not product_matches_major(pkg.product_name or "", major):
                continue
            try:
                parsed = parse_nevra(pkg.nevra)
            except ValueError:
                continue
            if parsed.get("arch") == "src":
                continue
            pkgs.append((pkg, parsed))
        if not pkgs:
            continue

        def_id = _qid("def", f"{major}:{advisory.name}")
        definition = ET.SubElement(
            definitions,
            f"{{{OVAL_NS}}}definition",
            {
                "id": def_id,
                "version": "1",
                "class": "patch",
            },
        )
        metadata = ET.SubElement(definition, f"{{{OVAL_NS}}}metadata")
        ET.SubElement(metadata, f"{{{OVAL_NS}}}title").text = (
            f"{advisory.name}: {advisory.synopsis}"
        )
        affected = ET.SubElement(
            metadata,
            f"{{{OVAL_NS}}}affected",
            {"family": "unix"},
        )
        ET.SubElement(affected, f"{{{OVAL_NS}}}platform").text = (
            f"Rocky Linux {major}"
        )
        for cve_row in advisory.cves or []:
            ET.SubElement(
                metadata,
                f"{{{OVAL_NS}}}reference",
                {
                    "source": "CVE",
                    "ref_id": cve_row.cve,
                    "ref_url": f"{attribution.CVE_URL_BASE}/{cve_row.cve}",
                },
            )
        ET.SubElement(
            metadata,
            f"{{{OVAL_NS}}}reference",
            {
                "source": "RLSA",
                "ref_id": advisory.name,
                "ref_url": f"{attribution.UI_ERRATA_BASE}/{advisory.name}",
            },
        )
        ET.SubElement(metadata, f"{{{OVAL_NS}}}description").text = (
            advisory.description or advisory.topic or advisory.synopsis or ""
        )
        advisory_el = ET.SubElement(metadata, f"{{{OVAL_NS}}}advisory")
        issued = advisory.rocky_published_at or advisory.published_at
        if issued:
            ET.SubElement(
                advisory_el,
                f"{{{OVAL_NS}}}issued",
                {"date": issued.strftime("%Y-%m-%d")},
            )
        ET.SubElement(advisory_el, f"{{{OVAL_NS}}}severity").text = (
            (advisory.severity or "None").capitalize()
        )

        criteria = ET.SubElement(
            definition, f"{{{OVAL_NS}}}criteria", {"operator": "OR"}
        )

        # Module-aware grouping: one criterion per unique NEVR (any arch).
        seen_nevr = set()
        for pkg, parsed in pkgs:
            nevr_key = (
                parsed["name"],
                str(parsed.get("epoch") or "0"),
                parsed["version"],
                parsed["release"],
            )
            if nevr_key in seen_nevr:
                continue
            seen_nevr.add(nevr_key)

            name = parsed["name"]
            epoch = str(parsed.get("epoch") or "0")
            version = parsed["version"]
            release = parsed["release"]
            evr = f"{epoch}:{version}-{release}"

            test_id = _qid("tst", f"rpm:{name}:{evr}")
            object_id = _qid("obj", f"rpm:{name}")
            state_id = _qid("ste", f"rpm:{name}:{evr}")

            criterion = ET.SubElement(
                criteria,
                f"{{{OVAL_NS}}}criterion",
                {
                    "test_ref": test_id,
                    "comment": f"{name} is earlier than {evr}",
                },
            )
            _ = criterion  # criterion is attached via SubElement

            if test_id not in test_ids:
                test_ids.add(test_id)
                test_el = ET.SubElement(
                    tests,
                    f"{{{LINUX_NS}}}rpminfo_test",
                    {
                        "id": test_id,
                        "version": "1",
                        "check": "at least one",
                        "comment": f"{name} earlier than {evr}",
                    },
                )
                ET.SubElement(
                    test_el,
                    f"{{{LINUX_NS}}}object",
                    {"object_ref": object_id},
                )
                ET.SubElement(
                    test_el,
                    f"{{{LINUX_NS}}}state",
                    {"state_ref": state_id},
                )

            if object_id not in object_ids:
                object_ids.add(object_id)
                obj = ET.SubElement(
                    objects,
                    f"{{{LINUX_NS}}}rpminfo_object",
                    {"id": object_id, "version": "1"},
                )
                ET.SubElement(obj, f"{{{LINUX_NS}}}name").text = name

            if state_id not in state_ids:
                state_ids.add(state_id)
                state = ET.SubElement(
                    states,
                    f"{{{LINUX_NS}}}rpminfo_state",
                    {"id": state_id, "version": "1"},
                )
                ET.SubElement(
                    state,
                    f"{{{LINUX_NS}}}evr",
                    {
                        "datatype": "evr_string",
                        "operation": "less than",
                    },
                ).text = evr

                if pkg.module_name and pkg.module_stream:
                    ET.SubElement(
                        state,
                        f"{{{LINUX_NS}}}extended_name",
                    ).text = (
                        f"{pkg.module_name}:{pkg.module_stream}"
                    )

    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def oval_filename(major: int) -> str:
    return f"org.rockylinux.rlsa-{major}.xml"
