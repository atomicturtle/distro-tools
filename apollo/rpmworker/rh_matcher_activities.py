import datetime
import re
from dataclasses import dataclass
from typing import Optional
from xml.etree import ElementTree as ET
from temporalio import activity
from tortoise.transactions import in_transaction

from apollo.db import SupportedProduct, SupportedProductsRhMirror, SupportedProductsRpmRepomd, SupportedProductsRpmRhOverride, SupportedProductsRhBlock
from apollo.db import RedHatAdvisory, Advisory, AdvisoryAffectedProduct, AdvisoryCVE, AdvisoryFix, AdvisoryPackage
from apollo.rpmworker import repomd
from apollo.rpmworker.nvra_match import (
    find_nvra_alias,
    lowest_compatible_pkgs,
    select_clone_pkgs,
)
from apollo.rpm_helpers import parse_dist_version, parse_nevra
from apollo.rhcsaf import fix_source_url

from common.logger import Logger

RHEL_CONTAINER_RE = re.compile(r"rhel(?:\d|)\/")


def _normalize_module_nevra_key(nevra_key: str) -> str:
    return nevra_key.replace(".rocky", "")


def _lookup_module_pkgs(module_pkgs: dict, nevra_key: str):
    if nevra_key in module_pkgs:
        return module_pkgs[nevra_key]
    normalized = _normalize_module_nevra_key(nevra_key)
    return module_pkgs.get(normalized)


def _module_fields_from_yaml(module_pkgs: dict, nevra_key: str):
    data = _lookup_module_pkgs(module_pkgs, nevra_key)
    if not data:
        return None, None, None, None
    return data[0], data[1], data[2], data[3]


def _enrich_module_version_from_yaml(module_pkgs, module_name, module_stream, module_version, module_context):
    if module_version and module_context:
        return module_version, module_context
    if not module_name or not module_stream:
        return module_version, module_context
    for data in module_pkgs.values():
        if data[0] == module_name and data[1] == module_stream:
            return data[2], data[3]
    return module_version, module_context


def _rh_modules_by_cleaned_nevra(advisory) -> dict:
    rh_modules = {}
    for advisory_pkg in advisory.packages:
        if not advisory_pkg.module_name:
            continue
        cleaned, _ = repomd.clean_nvra(advisory_pkg.nevra)
        rh_modules[cleaned] = {
            "module_name": advisory_pkg.module_name,
            "module_stream": advisory_pkg.module_stream,
            "module_version": advisory_pkg.module_version,
            "module_context": advisory_pkg.module_context,
        }
    return rh_modules


def _resolve_modular_package_fields(
    release: str,
    nevra: str,
    cleaned_rh_nvra: str,
    module_pkgs: dict,
    rh_modules_by_cleaned: dict,
):
    module_context = None
    module_name = None
    module_stream = None
    module_version = None
    if ".module+" not in release:
        return module_name, module_stream, module_version, module_context

    module_name, module_stream, module_version, module_context = _module_fields_from_yaml(
        module_pkgs, nevra.removesuffix(".rpm")
    )
    if not module_name:
        rh = rh_modules_by_cleaned.get(cleaned_rh_nvra)
        if rh:
            module_name = rh["module_name"]
            module_stream = rh["module_stream"]
            module_version = rh.get("module_version")
            module_context = rh.get("module_context")
    module_version, module_context = _enrich_module_version_from_yaml(
        module_pkgs,
        module_name,
        module_stream,
        module_version,
        module_context,
    )
    return module_name, module_stream, module_version, module_context


@dataclass
class NewPackage:
    nevra: str
    checksum: str
    checksum_type: str
    module_context: str
    module_name: str
    module_stream: str
    module_version: str
    repo_name: str
    package_name: str
    mirror_id: int
    supported_product_id: int
    product_name: str


def _is_historical_mirror(mirror) -> bool:
    """Vault/point-release mirrors used for first clone and repair, not daily rematch."""
    name = getattr(mirror, "name", None) or ""
    return " [vault " in name


SHIP_PRODUCT_ARCHES = {
    "x86_64",
    "aarch64",
    "ppc64le",
    "s390x",
    "riscv64",
    "i686",
}


def _product_arch_for_package(parsed_arch: str, product_name: str) -> Optional[str]:
    """Arch yum/updateinfo join on. ``src`` is not a repo arch.

    ``noarch`` RPMs live in arch-specific repos; use the stream label's arch
    (``Rocky Linux 10 x86_64``) so they still appear in x86_64 updateinfo.
    """
    if parsed_arch in SHIP_PRODUCT_ARCHES:
        return parsed_arch
    if parsed_arch == "noarch" and product_name:
        token = product_name.rsplit(" ", 1)[-1]
        if token in SHIP_PRODUCT_ARCHES:
            return token
        return "x86_64"
    return None


def affected_product_rows_from_packages(
    advisory_id: int,
    variant: str,
    packages: list,
) -> list[dict]:
    """One affected-product row per (stream name, major, arch) actually cloned.

    Mirror lists include every repo that was walked (vault 9.0, SIG, EL10) even
    when no package from that major landed. SPA ``affectedProducts`` must follow
    NEVRAs, not the walk. Skip ``src`` — updateinfo filters ``arch=x86_64`` and
    Postgres unique ``(advisory_id, name)`` plus insert-then-delete would
    otherwise drop ship-arch rows and leave only ``Rocky Linux 10 src``.
    """
    rows = {}
    src_fallback = []
    for pkg in packages:
        try:
            parsed = parse_nevra(pkg.nevra)
        except (ValueError, AttributeError, TypeError):
            continue
        dist = parse_dist_version(parsed["release"])
        major = dist["major"]
        if major is None:
            continue
        product_name = getattr(pkg, "product_name", None) or ""
        arch = _product_arch_for_package(parsed["arch"], product_name)
        if arch is None:
            if parsed["arch"] == "src":
                src_fallback.append((pkg, major))
            continue
        name = f"{variant} {major} {arch}"
        key = (variant, name, major, arch)
        if key in rows:
            continue
        rows[key] = {
            "advisory_id": advisory_id,
            "variant": variant,
            "name": name,
            "major_version": major,
            "minor_version": None,
            "arch": arch,
            "supported_product_id": pkg.supported_product_id,
        }
    if not rows:
        for pkg, major in src_fallback:
            arch = "x86_64"
            name = f"{variant} {major} {arch}"
            key = (variant, name, major, arch)
            if key in rows:
                continue
            rows[key] = {
                "advisory_id": advisory_id,
                "variant": variant,
                "name": name,
                "major_version": major,
                "minor_version": None,
                "arch": arch,
                "supported_product_id": pkg.supported_product_id,
            }
    return list(rows.values())


def stream_product_name(mirror) -> str:
    """Label scanners should join to the live major-stream repo, not a frozen minor.

    Mirror rows named ``Rocky Linux 9.6 aarch64`` freeze the point release that
    was current at clone time. Hosts on 9.7 then miss the advisory (distro-tools#71).
    Collapse ``{major}.{minor}`` in the display name when match_minor_version is
    set. Names like ``Rocky Linux 10 riscv64`` are left untouched.

    Historical mirrors are named ``Rocky Linux 10 x86_64 [vault 10.0]`` so the
    scanner label stays ``Rocky Linux 10 x86_64``.
    """
    name = mirror.name
    if name and " [vault " in name:
        name = name.split(" [vault ", 1)[0]
    major = mirror.match_major_version
    minor = mirror.match_minor_version
    if name and major is not None and minor is not None:
        needle = f"{major}.{minor}"
        if needle in name:
            return name.replace(needle, str(major), 1)
    return name


def advisory_clone_published_at(advisory, fallback):
    """Clone publish time is the RH issued date, not the ingest clock."""
    issued = getattr(advisory, "red_hat_issued_at", None)
    if issued is not None:
        return issued
    return fallback


async def create_or_update_advisory_packages(
    advisory: Advisory,
    packages: list[NewPackage],
    update_advisory: bool = False,
    replace_packages: bool = False,
) -> None:
    """
    Attach packages to a cloned advisory.

    First clone (no existing rows): insert matched NEVRAs.
    Daily rematch (update_advisory, not replace_packages): fill null module
    fields and refresh product_name on NEVRAs already present. Do not add or
    delete packages — an RLSA is a snapshot of what shipped.
    Repair (replace_packages): add missing NEVRAs and delete those not in the
    new match set (vault + current lowest-EVR rematch).
    """
    logger = Logger()
    logger.info("Creating or updating advisory packages for %s", advisory.name)

    existing_packages = await AdvisoryPackage.filter(advisory_id=advisory.id).all()
    existing_nevras = {pkg.nevra for pkg in existing_packages}
    new_nevras = {pkg.nevra for pkg in packages}
    mutate_packages = (not existing_packages) or replace_packages

    # Add new packages
    new_packages = []
    if mutate_packages:
        for pkg in packages:
            if pkg.nevra not in existing_nevras:
                new_packages.append(
                    AdvisoryPackage(
                        advisory_id=advisory.id,
                        nevra=pkg.nevra,
                        checksum=pkg.checksum,
                        checksum_type=pkg.checksum_type,
                        module_context=pkg.module_context,
                        module_name=pkg.module_name,
                        module_stream=pkg.module_stream,
                        module_version=pkg.module_version,
                        repo_name=pkg.repo_name,
                        package_name=pkg.package_name,
                        supported_products_rh_mirror_id=pkg.mirror_id,
                        supported_product_id=pkg.supported_product_id,
                        product_name=pkg.product_name,
                    )
                )
    if new_packages:
        logger.info("Adding %d new packages to advisory %s", len(new_packages), advisory.name)
        await AdvisoryPackage.bulk_create(new_packages, ignore_conflicts=True)
    elif mutate_packages:
        logger.info("No new packages to add to advisory %s", advisory.name)
    else:
        logger.info(
            "Leaving %d existing packages on %s (snapshot rematch)",
            len(existing_packages),
            advisory.name,
        )

    # Fill missing module fields on existing packages (do not overwrite resolved streams)
    # and refresh product_name so rematch repairs frozen point-release labels.
    existing_by_nevra = {pkg.nevra: pkg for pkg in existing_packages}
    stale_product_ids = {}
    for pkg in packages:
        existing = existing_by_nevra.get(pkg.nevra)
        if not existing:
            continue
        if existing.product_name != pkg.product_name:
            stale_product_ids.setdefault(pkg.product_name, []).append(existing.id)
        if not existing.module_name:
            if not pkg.module_name:
                continue
            await AdvisoryPackage.filter(id=existing.id).update(
                module_name=pkg.module_name,
                module_stream=pkg.module_stream,
                module_version=pkg.module_version,
                module_context=pkg.module_context,
            )
    for product_name, ids in stale_product_ids.items():
        logger.info(
            "Updating product_name to %s on %d packages for advisory %s",
            product_name,
            len(ids),
            advisory.name,
        )
        await AdvisoryPackage.filter(id__in=ids).update(product_name=product_name)

    # Remove packages not in the new list only on explicit repair.
    if replace_packages:
        nevras_to_remove = existing_nevras - new_nevras
        if nevras_to_remove:
            logger.info("Removing %d packages from advisory %s", len(nevras_to_remove), advisory.name)
            await AdvisoryPackage.filter(advisory_id=advisory.id, nevra__in=list(nevras_to_remove)).delete()


async def create_or_update_advisory_cves(
    advisory: Advisory,
    cves: list,
    update_advisory: bool = False,
) -> None:
    """
    Add or update CVEs for the given advisory.
    Remove CVEs currently associated with advisory if they don't exist in the list passed in.
    """
    logger = Logger()
    logger.info("Creating or updating CVEs for advisory %s", advisory.name)

    # Build a map of existing CVEs by cve_id
    existing_cves = {cve.cve: cve for cve in await AdvisoryCVE.filter(advisory_id=advisory.id).all()}
    existing_cve_ids = set(existing_cves.keys())

    # Support both dicts and objects
    def extract_cve_id(cve_data):
        if isinstance(cve_data, dict):
            return cve_data["cve"]
        return getattr(cve_data, "cve", None)

    new_cve_ids = set()
    for cve_data in cves:
        cve_id = extract_cve_id(cve_data)
        if not cve_id:
            continue
        new_cve_ids.add(cve_id)
        existing = existing_cves.get(cve_id)
        cvss3_scoring_vector = (
            cve_data.get("cvss3_scoring_vector") if isinstance(cve_data, dict)
            else getattr(cve_data, "cvss3_scoring_vector", None)
        )
        cvss3_base_score = (
            cve_data.get("cvss3_base_score") if isinstance(cve_data, dict)
            else getattr(cve_data, "cvss3_base_score", None)
        )
        cwe = (
            cve_data.get("cwe") if isinstance(cve_data, dict)
            else getattr(cve_data, "cwe", None)
        )

        if existing:
            needs_update = (
                existing.cvss3_scoring_vector != cvss3_scoring_vector or
                str(existing.cvss3_base_score) != str(cvss3_base_score) or
                (existing.cwe or "") != (cwe or "")
            )
            if needs_update:
                logger.info("Updating CVE %s for advisory %s", cve_id, advisory.name)
                existing.cvss3_scoring_vector = cvss3_scoring_vector
                existing.cvss3_base_score = str(cvss3_base_score) if cvss3_base_score else None
                existing.cwe = cwe if cwe else None
                await existing.save()
        else:
            logger.info("Adding new CVE %s to advisory %s", cve_id, advisory.name)
            await AdvisoryCVE.create(
                advisory_id=advisory.id,
                cve=cve_id,
                cvss3_scoring_vector=cvss3_scoring_vector,
                cvss3_base_score=str(cvss3_base_score) if cvss3_base_score else None,
                cwe=cwe if cwe else None,
            )

    # Remove CVEs not in the new list
    if update_advisory:
        cves_to_remove = existing_cve_ids - new_cve_ids
        if cves_to_remove:
            logger.info("Removing %d CVEs from advisory %s", len(cves_to_remove), advisory.name)
            await AdvisoryCVE.filter(advisory_id=advisory.id, cve__in=list(cves_to_remove)).delete()

async def create_or_update_advisory_fixes(
    advisory: Advisory,
    fixes: list,
    update_advisory: bool = False,
) -> None:
    """
    Add fixes for the given advisory.
    Remove fixes currently associated with advisory if they don't exist in the list passed in.
    """
    logger = Logger()
    logger.info("Creating or updating fixes for advisory %s", advisory.name)

    existing_fixes = await AdvisoryFix.filter(advisory_id=advisory.id).all()
    existing_ticket_ids = {fix.ticket_id for fix in existing_fixes}

    new_ticket_ids = {fix.bugzilla_bug_id for fix in fixes if fix.bugzilla_bug_id}

    # Add new fixes
    new_fixes = []
    for fix in fixes:
        if fix.bugzilla_bug_id and fix.bugzilla_bug_id not in existing_ticket_ids:
            new_fixes.append(
                AdvisoryFix(
                    advisory_id=advisory.id,
                    ticket_id=fix.bugzilla_bug_id,
                    source=fix_source_url(fix.bugzilla_bug_id),
                    description=fix.description,
                )
            )

    if new_fixes:
        logger.info("Adding %d new fixes to advisory %s", len(new_fixes), advisory.name)
        await AdvisoryFix.bulk_create(new_fixes, ignore_conflicts=True)
    else:
        logger.info("No new fixes to add to advisory %s", advisory.name)

    # Remove fixes not in the new list
    if update_advisory:
        tickets_to_remove = existing_ticket_ids - new_ticket_ids
        if tickets_to_remove:
            logger.info("Removing %d fixes from advisory %s", len(tickets_to_remove), advisory.name)
            await AdvisoryFix.filter(advisory_id=advisory.id, ticket_id__in=list(tickets_to_remove)).delete()


async def create_or_update_advisory_affected_product(
    advisory: Advisory,
    product_name: str,
    mirrors: list[SupportedProductsRhMirror],
    update_advisory: bool = False,
    packages: Optional[list] = None,
    ) -> None:
    """
    Add affected products for the given advisory.
    Prefer cloned package NEVRAs. Fall back to the mirror list only when
    ``packages`` is None (no cloned set supplied). On update, drop products
    no longer represented.
    """
    logger = Logger()
    logger.info("Creating or updating affected products for advisory %s", advisory.name)

    existing_affected_products = await AdvisoryAffectedProduct.filter(advisory_id=advisory.id).all()
    existing_names = {ap.name for ap in existing_affected_products}

    # packages=None: first-clone fallback to the mirror walk. An explicit list
    # (including empty) is the cloned NEVRA set — never re-widen from mirrors.
    if packages is None:
        new_affected_products = []
    else:
        new_affected_products = affected_product_rows_from_packages(
            advisory.id, product_name, packages
        )
    if not new_affected_products and packages is None:
        for mirror in mirrors:
            new_affected_products.append(
                {
                    "advisory_id": advisory.id,
                    "variant": product_name,
                    "name": stream_product_name(mirror),
                    "major_version": mirror.match_major_version,
                    "minor_version": mirror.match_minor_version,
                    "arch": mirror.match_arch,
                    "supported_product_id": mirror.supported_product_id,
                }
            )

    # Postgres unique is (advisory_id, name), not tortoise unique_together.
    # Insert-then-delete with ignore_conflicts drops ship-arch rows when the
    # new name matches an old row (minor_version None vs 0) and then deletes
    # the old key — RLSA-2025:10073 kept only ``Rocky Linux 10 src``.
    if update_advisory:
        await AdvisoryAffectedProduct.filter(advisory_id=advisory.id).delete()
        existing_names = set()

    new_entries = []
    seen_names = set()
    for product in new_affected_products:
        name = product["name"]
        if name in existing_names or name in seen_names:
            continue
        seen_names.add(name)
        new_entries.append(
            AdvisoryAffectedProduct(
                advisory_id=advisory.id,
                variant=product["variant"],
                name=name,
                major_version=product["major_version"],
                minor_version=product["minor_version"],
                arch=product["arch"],
                supported_product_id=product.get("supported_product_id"),
            )
        )

    if new_entries:
        logger.info(
            "Adding %d new affected products to advisory %s",
            len(new_entries),
            advisory.name,
        )
        await AdvisoryAffectedProduct.bulk_create(new_entries)
    else:
        logger.info("No new affected products to add to advisory %s", advisory.name)


@activity.defn
async def get_supported_products_with_rh_mirrors(filter_major_versions: Optional[list[int]] = None) -> list[int]:
    """
    Get supported product IDs that has an RH mirror configuration
    Note: filter_major_versions parameter is kept for backward compatibility but not used at this level.
    Filtering now happens at the mirror level within match_rh_repos activity.
    """
    logger = Logger()
    rh_mirrors = await SupportedProductsRhMirror.filter(active=True).prefetch_related(
        "rpm_repomds",
    )
    ret = []
    for rh_mirror in rh_mirrors:
        if rh_mirror.supported_product_id not in ret and rh_mirror.rpm_repomds:
            logger.debug(f"Adding rh_mirror.supported_product_id ({rh_mirror.supported_product_id})")
            ret.append(rh_mirror.supported_product_id)

    return ret


def rh_advisory_matches_major(advisory: RedHatAdvisory, major: int) -> bool:
    """True when this RHSA/RHBA/RHEA belongs on a Rocky mirror of ``major``.

    Prefer ``affected_products``. If none are loaded, fall back to dist tags
    on the RH packages so rematch of a named set does not send an EL10
    advisory into EL8/EL9 indexes (cleaned NVR would otherwise collide).
    """
    products = getattr(advisory, "affected_products", None) or []
    saw_product = False
    for product in products:
        try:
            product_major = int(product.major_version)
        except (TypeError, ValueError, AttributeError):
            continue
        saw_product = True
        if product_major == major:
            return True
    if saw_product:
        return False
    for pkg in getattr(advisory, "packages", None) or []:
        try:
            parsed = parse_nevra(pkg.nevra)
        except (ValueError, AttributeError, TypeError):
            continue
        dist = parse_dist_version(parsed["release"])
        if dist["major"] == major:
            return True
    return False


async def get_matching_rh_advisories(
    mirror: SupportedProductsRhMirror
) -> list[RedHatAdvisory]:
    # First get advisories that matches the mirrored product
    # And also the overrides
    # Also exclude blocked advisories and advisories without packages
    #
    # NULL match_minor_version means "any minor of this major". EL8/9 CSAF
    # rows store minor as NULL; EL10 stores 0/1/2, so a NULL-equals-NULL
    # filter would match nothing for Rocky 10 stream mirrors.
    filters = {
        "affected_products__variant": mirror.match_variant,
        "affected_products__major_version": mirror.match_major_version,
        "affected_products__arch": mirror.match_arch,
    }
    if mirror.match_minor_version is not None:
        filters["affected_products__minor_version"] = mirror.match_minor_version
    advisories = await RedHatAdvisory.filter(**filters).order_by(
        "red_hat_issued_at"
    ).prefetch_related(
        "packages",
        "cves",
        "bugzilla_tickets",
    )

    override_ids = []
    overrides = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror_id=mirror.id,
        updated_at__isnull=True,
    ).prefetch_related(
        "red_hat_advisory",
        "red_hat_advisory__packages",
        "red_hat_advisory__cves",
        "red_hat_advisory__bugzilla_tickets",
    )
    for override in overrides:
        override_ids.append(override.red_hat_advisory_id)
        advisories.append(override.red_hat_advisory)

    blocked = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror_id=mirror.id
    ).all()
    blocked_ids = []
    now = datetime.datetime.now(datetime.timezone.utc)
    for b in blocked:
        if b.red_hat_advisory_id in override_ids:
            continue
        delta = now - b.created_at
        if delta.days >= 14:
            blocked_ids.append(b.red_hat_advisory_id)

    # Remove all advisories without packages and blocked advisories
    final = []
    final_ids = []
    for advisory in advisories:
        if advisory.packages and advisory.id not in blocked_ids:
            if advisory.id not in final_ids:
                final.append(advisory)
                final_ids.append(advisory.id)
    return final


async def clone_advisory(
    product: SupportedProduct,
    mirrors: list[SupportedProductsRhMirror],
    advisory: RedHatAdvisory,
    all_pkgs: list[ET.ElementTree],
    module_pkgs: dict,
    published_at: datetime.datetime,
    replace_packages: bool = False,
):
    logger = Logger()
    logger.info("Cloning advisory %s to %s", advisory.name, product.name)

    acceptable_arches = list({x.match_arch for x in mirrors})
    acceptable_arches.extend(["src", "noarch"])
    for mirror in mirrors:
        if mirror.match_arch == "x86_64":
            acceptable_arches.append("i686")
            break

    # Generate dictionary of clean advisory nvras
    clean_advisory_nvras = {}
    for advisory_pkg in advisory.packages:
        try:
            results = parse_nevra(advisory_pkg.nevra)
        except ValueError as e:
            logger.warning(f"Skipping invalid NEVRA '{advisory_pkg.nevra}': {e}")
            continue
        advisory_pkg_arch = results["arch"]
        if advisory_pkg_arch not in acceptable_arches:
            continue
        cleaned, raw = repomd.clean_nvra(advisory_pkg.nevra)
        if cleaned not in clean_advisory_nvras:
            clean_advisory_nvras[cleaned] = advisory_pkg.nevra

    if not clean_advisory_nvras:
        logger.info(
            "Blocking advisory %s, no packages match arches",
            advisory.name,
        )
        await SupportedProductsRhBlock.bulk_create(
            [
                SupportedProductsRhBlock(
                    **{
                        "supported_products_rh_mirror_id": mirror.id,
                        "red_hat_advisory_id": advisory.id,
                    }
                ) for mirror in mirrors
            ],
            ignore_conflicts=True,
        )
        return

    # Generate dictionary of all packages in the repomd
    pkg_nvras = {} # Populated from all_pkgs and contains a mapping of all pkg xml elemnts for each cleaned nvra
    # { cleaned_nvra: [pkg_xml_elem, pkg_xml_elem, ...] }
    pkg_name_map = {} # Populated from all_pkgs and contains a mapping of package name to all of the raw nvras associated with that package name
    # { pkg_name: [raw_nvra, raw_nvra, ...] }
    for pkgs in all_pkgs:
        for pkg in pkgs:
            cleaned, raw = repomd.clean_nvra_pkg(pkg)
            name = repomd.NVRA_RE.search(cleaned).group(1)
            if cleaned not in pkg_nvras:
                pkg_nvras[cleaned] = [pkg]
            else:
                pkg_nvras[cleaned].append(pkg)

            if name not in pkg_name_map:
                pkg_name_map[name] = []
            pkg_name_map[name].append(cleaned)

    # Alias advisory NVRA → repo NVRA via .rocky prefix or EVR >=.
    # clone_advisory prefers current-stream hits over vault; this map is
    # only used when the exact cleaned key has no satisfying package.
    nvra_alias = {}
    for advisory_nvra, advisory_nevra in clean_advisory_nvras.items():
        exact_pkgs = pkg_nvras.get(advisory_nvra, [])
        if lowest_compatible_pkgs(advisory_nevra, exact_pkgs):
            continue
        match = repomd.NVRA_RE.search(advisory_nvra)
        if not match:
            continue
        alias = find_nvra_alias(
            advisory_nvra,
            pkg_name_map.get(match.group(1), []),
            advisory_nevra=advisory_nevra,
            raw_pkg_nvras=pkg_nvras,
        )
        if alias:
            nvra_alias[advisory_nvra] = alias

    async with in_transaction():
        # Create advisory
        name = f"{product.code.code}{advisory.name.removeprefix('RH')}"
        synopsis = advisory.synopsis.replace(
            "Red Hat Enterprise Linux", product.name
        )
        synopsis = synopsis.replace("RHEL", product.name)
        synopsis = RHEL_CONTAINER_RE.sub("", synopsis)
        synopsis = synopsis.replace("Red Hat", product.vendor)
        synopsis = synopsis.replace(advisory.name, name)
        description = advisory.description.replace(
            "Red Hat Enterprise Linux", product.name
        )
        description = description.replace("RHEL", product.name)
        description = RHEL_CONTAINER_RE.sub("", description)
        description = description.replace("Red Hat", product.vendor)
        description = description.replace(advisory.name, name)

        existing_advisory = await Advisory.filter(name=name).get_or_none()
        update_advisory = False
        if not existing_advisory:
            logger.info(f"Creating advisory {name}")
            new_advisory = await Advisory.create(
                name=name,
                synopsis=synopsis,
                description=description,
                kind=advisory.kind,
                severity=advisory.severity,
                red_hat_advisory_id=advisory.id,
                published_at=advisory_clone_published_at(advisory, published_at),
                topic=advisory.topic,
            )
        else:
            update_advisory = True
            new_advisory = existing_advisory

        # Clone packages
        new_pkgs = []
        rh_modules_by_cleaned = _rh_modules_by_cleaned_nevra(advisory)
        historical_ids = {
            str(mirror.id)
            for mirror in mirrors
            if _is_historical_mirror(mirror)
        }
        for cleaned_rh_nvra, rh_nevra in clean_advisory_nvras.items():
            advisory_nvra = cleaned_rh_nvra
            match = repomd.NVRA_RE.search(cleaned_rh_nvra)
            pool: list = []
            seen_pkg = set()
            names = []
            if match:
                names.append(match.group(1))
            for cleaned in names and pkg_name_map.get(names[0], []) or []:
                for pkg in pkg_nvras.get(cleaned, []):
                    ident = id(pkg)
                    if ident in seen_pkg:
                        continue
                    seen_pkg.add(ident)
                    pool.append(pkg)
            if cleaned_rh_nvra in nvra_alias:
                advisory_nvra = nvra_alias[cleaned_rh_nvra]
                for pkg in pkg_nvras.get(advisory_nvra, []):
                    ident = id(pkg)
                    if ident in seen_pkg:
                        continue
                    seen_pkg.add(ident)
                    pool.append(pkg)
            if not pool:
                pool = list(pkg_nvras.get(cleaned_rh_nvra, []))
            pkgs_to_process = select_clone_pkgs(
                rh_nevra, pool, historical_ids
            )
            if not pkgs_to_process:
                continue

            for pkg in pkgs_to_process:
                pkg_name = pkg.find(
                    "{http://linux.duke.edu/metadata/common}name"
                ).text
                version_tree = pkg.find(
                    "{http://linux.duke.edu/metadata/common}version"
                )
                version = version_tree.attrib["ver"]
                release = version_tree.attrib["rel"]
                epoch = version_tree.attrib["epoch"]
                arch = pkg.find(
                    "{http://linux.duke.edu/metadata/common}arch"
                ).text
                nevra = f"{pkg_name}-{epoch}:{version}-{release}.{arch}.rpm"

                source_rpm = pkg.find(
                    "{http://linux.duke.edu/metadata/common}format"
                ).find("{http://linux.duke.edu/metadata/rpm}sourcerpm")

                package_name = None
                if advisory_nvra.endswith(".src.rpm"
                                         ) or advisory_nvra.endswith(".src"):
                    source_nvra = repomd.NVRA_RE.search(advisory_nvra)
                    if source_nvra:
                        package_name = source_nvra.group(1)
                elif source_rpm is not None and source_rpm.text:
                    source_nvra = repomd.NVRA_RE.search(source_rpm.text)
                    if source_nvra:
                        package_name = source_nvra.group(1)

                if not package_name:
                    logger.warning(
                        "Could not extract package_name for %s in advisory %s, skipping package",
                        nevra,
                        advisory.name,
                    )
                    continue

                checksum_tree = pkg.find(
                    "{http://linux.duke.edu/metadata/common}checksum"
                )
                checksum = checksum_tree.text
                checksum_type = checksum_tree.attrib["type"]

                module_name, module_stream, module_version, module_context = _resolve_modular_package_fields(
                    release,
                    nevra,
                    cleaned_rh_nvra,
                    module_pkgs,
                    rh_modules_by_cleaned,
                )

                for mirror in mirrors:
                    if pkg.attrib["mirror_id"] != str(mirror.id):
                        continue
                    new_pkgs.append(
                        NewPackage(
                            nevra=nevra,
                            checksum=checksum,
                            checksum_type=checksum_type,
                            module_context=module_context,
                            module_name=module_name,
                            module_stream=module_stream,
                            module_version=module_version,
                            repo_name=pkg.attrib["repo_name"],
                            package_name=package_name,
                            mirror_id=mirror.id,
                            supported_product_id=mirror.supported_product_id,
                            product_name=stream_product_name(mirror),
                        )
                    )

        if not new_pkgs:
            if existing_advisory:
                logger.info(
                    "No packages in current index for %s; leaving existing clone",
                    advisory.name,
                )
                return
            logger.info(
                "Blocking advisory %s, no packages",
                advisory.name,
            )
            await new_advisory.delete()
            await SupportedProductsRhBlock.bulk_create(
                [
                    SupportedProductsRhBlock(
                        **{
                            "supported_products_rh_mirror_id": mirror.id,
                            "red_hat_advisory_id": advisory.id,
                        }
                    ) for mirror in mirrors
                ],
                ignore_conflicts=True,
            )
            return

        await create_or_update_advisory_packages(
            new_advisory,
            new_pkgs,
            update_advisory,
            replace_packages=replace_packages,
        )

        # Clone CVEs
        if advisory.cves:
            await create_or_update_advisory_cves(new_advisory, advisory.cves, update_advisory)

        # Clone fixes
        if advisory.bugzilla_tickets:
            await create_or_update_advisory_fixes(
                new_advisory,
                advisory.bugzilla_tickets,
                update_advisory
                )

        # Add affected products
        await create_or_update_advisory_affected_product(
            new_advisory,
            product.name,
            mirrors,
            update_advisory,
            packages=new_pkgs,
        )

        # Construct topic
        package_names = list({p.package_name for p in new_pkgs})
        affected_majors = set()
        for pkg in new_pkgs:
            try:
                major = parse_dist_version(parse_nevra(pkg.nevra)["release"])["major"]
            except (ValueError, TypeError, KeyError):
                continue
            if major is not None:
                affected_majors.add(major)
        affected_products = [f"{product.name} {major}" for major in sorted(affected_majors)]
        topic = f"""An update is available for {', '.join(package_names)}.
This update affects {', '.join(affected_products)}.
A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE list"""
        new_advisory.topic = topic

        await new_advisory.save()

        # Block advisory from being attempted to be mirrored again
        await SupportedProductsRhBlock.bulk_create(
            [
                SupportedProductsRhBlock(
                    **{
                        "supported_products_rh_mirror_id": mirror.id,
                        "red_hat_advisory_id": advisory.id,
                    }
                ) for mirror in mirrors
            ],
            ignore_conflicts=True,
        )

        # Set update_at to now for any overrides for advisory
        await SupportedProductsRpmRhOverride.filter(
            red_hat_advisory_id=advisory.id,
            supported_products_rh_mirror_id__in=[x.id for x in mirrors],
        ).update(updated_at=datetime.datetime.utcnow())


async def process_repomd(
    mirror: SupportedProductsRhMirror,
    rpm_repomd: SupportedProductsRpmRepomd,
    advisories: list[RedHatAdvisory],
    indexed_pkgs: Optional[list] = None,
    wanted_pkg_names: Optional[set] = None,
):
    logger = Logger()
    all_pkgs = []
    urls_to_fetch = [
        rpm_repomd.url, rpm_repomd.debug_url, rpm_repomd.source_url
    ]
    module_packages = {}
    for url in urls_to_fetch:
        if not url:
            continue
        logger.info("Fetching %s", url)
        try:
            repomd_xml = await repomd.download_xml(url)
            primary_xml = await repomd.get_data_from_repomd(
                url, "primary", repomd_xml
            )
        except Exception as exc:
            logger.warning("Skipping %s: %s", url, exc)
            continue
        if primary_xml is None:
            continue
        pkgs = primary_xml.findall(
            "{http://linux.duke.edu/metadata/common}package"
        )
        all_pkgs.extend(pkgs)

        try:
            module_yaml_data = await repomd.get_data_from_repomd(
                url,
                "modules",
                repomd_xml,
                is_yaml=True,
            )
        except Exception as exc:
            logger.warning("Skipping modules.yaml for %s: %s", url, exc)
            module_yaml_data = None
        if module_yaml_data:
            logger.info("Found modules.yaml")
            for module_data in module_yaml_data:
                if module_data.get("document") != "modulemd":
                    continue
                data = module_data.get("data")
                if not data.get("artifacts"):
                    continue
                for nevra in data.get("artifacts").get("rpms"):
                    module_packages[nevra] = (
                        data.get("name"),
                        data.get("stream"),
                        data.get("version"),
                        data.get("context"),
                    )
                    normalized = _normalize_module_nevra_key(nevra)
                    if normalized != nevra:
                        module_packages[normalized] = module_packages[nevra]

    ret = {}
    raw_pkg_nvras = {}
    pkg_name_map = {}
    for pkg in all_pkgs:
        # in the case of a module nvra the cleaned variable
        # becomes the package stripped of any module information
        # and with the nvra prepended with 'module.'
        cleaned, raw = repomd.clean_nvra_pkg(pkg)
        match = repomd.NVRA_RE.search(cleaned)
        if not match:
            logger.warning(
                "Skipping package with unrecognized NVRA: %s", cleaned
            )
            continue
        name = match.group(1)

        pkg.set("mirror_id", str(mirror.id))
        pkg.set("repo_name", rpm_repomd.repo_name)
        if cleaned not in raw_pkg_nvras:
            raw_pkg_nvras[cleaned] = []
        raw_pkg_nvras[cleaned].append(pkg)

        if name not in pkg_name_map:
            pkg_name_map[name] = []
        if cleaned not in pkg_name_map[name]:
            pkg_name_map[name].append(cleaned)

    # Now check against advisories, and see if we're matching any
    # If we match, that means we can start creating the supporting
    # mirror advisories
    for advisory in advisories:
        logger.debug(f"Processing advisory: {advisory.name} inside of `process_repomd` for {mirror.name}")
        clean_advisory_nvras = {}
        nvra_alias = {}
        # Loop through each package in the advisory and check if we
        # have a match from the rocky repos
        for advisory_pkg in advisory.packages:
            # cleaned will strip out module specific info from a package name
            # and prepend 'module.' to the name for modular packages.
            cleaned, raw = repomd.clean_nvra(advisory_pkg.nevra)
            try:
                results = parse_nevra(advisory_pkg.nevra)
            except ValueError as e:
                logger.warning(f"Skipping invalid NEVRA '{advisory_pkg.nevra}': {e}")
                continue
            # Use cleaned NVRA name (includes "module." prefix) so modular
            # packages hit the same pkg_name_map keys as repo indexing.
            cleaned_match = repomd.NVRA_RE.search(cleaned)
            lookup_name = (
                cleaned_match.group(1) if cleaned_match else results["name"]
            )
            if cleaned not in clean_advisory_nvras:
                exact_pkgs = raw_pkg_nvras.get(cleaned, [])
                if not lowest_compatible_pkgs(advisory_pkg.nevra, exact_pkgs):
                    # Prefix (.rocky) or EVR >= when Rocky already ships newer
                    alias = find_nvra_alias(
                        cleaned,
                        pkg_name_map.get(lookup_name, []),
                        advisory_nevra=advisory_pkg.nevra,
                        raw_pkg_nvras=raw_pkg_nvras,
                    )
                    if alias:
                        nvra_alias[cleaned] = alias
                clean_advisory_nvras[cleaned] = advisory_pkg.nevra

        if not clean_advisory_nvras:
            logger.debug(f"No cleaned packages for {advisory.name}, moving on.")
            continue

        matched_pkgs = set()
        for nevra, rh_nevra in clean_advisory_nvras.items():
            selected = lowest_compatible_pkgs(
                rh_nevra, raw_pkg_nvras.get(nevra, [])
            )
            if not selected and nevra in nvra_alias:
                logger.debug(f"nevra: {nevra}")
                logger.debug(f"nvra_alias[nevra]: {nvra_alias[nevra]}")
                selected = lowest_compatible_pkgs(
                    rh_nevra, raw_pkg_nvras.get(nvra_alias[nevra], [])
                )
            for pkg in selected:
                pkg.set("repo_name", rpm_repomd.repo_name)
                pkg.set("mirror_id", str(mirror.id))
                matched_pkgs.add(pkg)

        if matched_pkgs:
            logger.debug(f"Found packages for {advisory.name}")
            ret.update(
                {
                    advisory.name:
                        {
                            "advisory": advisory,
                            "packages": [matched_pkgs],
                            "module_packages": module_packages,
                        }
                }
            )
        else:
            logger.debug(f"No matching packages found for {advisory.name} inside of {mirror.name}")

    if indexed_pkgs is not None:
        if wanted_pkg_names:
            for pkg in all_pkgs:
                name_el = pkg.find(
                    "{http://linux.duke.edu/metadata/common}name"
                )
                if name_el is None or name_el.text not in wanted_pkg_names:
                    continue
                if name_el.text.endswith("-debuginfo") or name_el.text.endswith(
                    "-debugsource"
                ):
                    continue
                arch_el = pkg.find(
                    "{http://linux.duke.edu/metadata/common}arch"
                )
                if arch_el is not None and arch_el.text == "src":
                    continue
                indexed_pkgs.append(pkg)
        else:
            indexed_pkgs.extend(all_pkgs)
    return ret


@activity.defn
async def match_rh_repos(params) -> None:
    """
    Process the repomd files for the supported product with optional major version filtering
    """
    # Handle both old format (int) and new format (dict) for backward compatibility
    if isinstance(params, int):
        supported_product_id = params
        filter_major_versions = None
        replace_packages = False
        include_historical = False
    else:
        supported_product_id = params["supported_product_id"]
        filter_major_versions = params.get("filter_major_versions")
        replace_packages = bool(params.get("replace_packages", False))
        include_historical = bool(params.get("include_historical", False))
    
    logger = Logger()
    supported_product = await SupportedProduct.filter(
        id=supported_product_id
    ).first().prefetch_related("rh_mirrors", "rh_mirrors__rpm_repomds", "code")

    all_advisories = {}

    for mirror in supported_product.rh_mirrors:
        if not mirror.active:
            logger.debug(f"Skipping inactive mirror {mirror.name}")
            continue
        if _is_historical_mirror(mirror) and not include_historical:
            logger.info("Skipping historical mirror %s", mirror.name)
            continue
        # Apply major version filtering if specified
        if filter_major_versions is not None and int(mirror.match_major_version) not in filter_major_versions:
            logger.debug(f"Skipping mirror {mirror.name} with major version {mirror.match_major_version} due to filtering")
            continue
        logger.info("Processing mirror: %s", mirror.name)
        advisories = await get_matching_rh_advisories(mirror)
        for rpm_repomd in mirror.rpm_repomds:
            if rpm_repomd.arch != mirror.match_arch:
                logger.debug(f"Skipping due to {rpm_repomd.arch} != {mirror.match_arch}")
                continue
            advisory_map = await process_repomd(mirror, rpm_repomd, advisories)
            if advisory_map:
                published_at = None
                if rpm_repomd.production:
                    published_at = datetime.datetime.utcnow()
                for advisory_name, obj in advisory_map.items():
                    logger.debug(f"Processing advisory: {advisory_name} for {mirror.name}")
                    if advisory_name in all_advisories:
                        all_advisories[advisory_name]["packages"].extend(
                            obj["packages"]
                        )
                        all_advisories[advisory_name]["mirrors"].append(mirror)

                        for key, val in obj["module_packages"].items():
                            all_advisories[advisory_name]["module_packages"][
                                key] = val
                    else:
                        new_obj = dict(obj)
                        new_obj["published_at"] = published_at
                        new_obj["mirrors"] = [mirror]
                        all_advisories.update({advisory_name: new_obj})

    for advisory_name, obj in all_advisories.items():
        logger.debug(f"Attempting to clone advisory: {advisory_name}")
        await clone_advisory(
            supported_product,
            list(set(obj["mirrors"])),
            obj["advisory"],
            obj["packages"],
            obj["module_packages"],
            obj["published_at"],
            replace_packages=replace_packages,
        )


@activity.defn
async def block_remaining_rh_advisories(supported_product_id: int) -> None:
    mirrors = await SupportedProductsRhMirror.filter(
        supported_product_id=supported_product_id,
        active=True
    )
    for mirror in mirrors:
        advisories = await get_matching_rh_advisories(mirror)
        await SupportedProductsRhBlock.bulk_create(
            [
                SupportedProductsRhBlock(
                    **{
                        "supported_products_rh_mirror_id": mirror.id,
                        "red_hat_advisory_id": advisory.id,
                    }
                ) for advisory in advisories
            ],
            ignore_conflicts=True
        )


@activity.defn
async def clear_rh_blocks_for_product(supported_product_id: int) -> int:
    """
    Delete RhBlocks for a product so matcher can retry (EVR≥ rematch).

    RhBlock is an operator rematch throttle, not a public CVE status.
    """
    mirrors = await SupportedProductsRhMirror.filter(
        supported_product_id=supported_product_id,
    )
    mirror_ids = [m.id for m in mirrors]
    if not mirror_ids:
        return 0
    deleted = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror_id__in=mirror_ids,
    ).delete()
    # Tortoise delete returns a tuple (count, details) or count depending on version
    if isinstance(deleted, tuple):
        return int(deleted[0])
    return int(deleted or 0)

