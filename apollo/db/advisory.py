import datetime
import re
from typing import Optional

from tortoise import connections

from apollo.db import Advisory

_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def naive_utc(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    """Bind timestamps as naive UTC for ``timestamptz`` query args.

    FastAPI parses ISO-8601 ``after``/``before`` as timezone-aware datetimes.
    asyncpg raises when those are sent to a ``timestamp`` bind, which is why
    ``GET /api/v3/osv/?after=...`` returned HTTP 500.
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


async def fetch_advisories(
    size: int,
    page_offset: int,
    keyword: Optional[str],
    product: Optional[str],
    before: Optional[datetime.datetime],
    after: Optional[datetime.datetime],
    cve: Optional[str],
    synopsis: Optional[str],
    severity: Optional[str],
    kind: Optional[str],
    fetch_related: bool = False,
    fetch_packages: bool = True,
    require_cves: bool = False,
) -> tuple[int, list[Advisory]]:
    if cve:
        cve = cve.strip()
        if _CVE_ID.match(cve):
            cve = cve.upper()

    a = """
        with vars (search, size, page_offset, product, before, after, cve, synopsis, severity, kind) as (
            values ($1 :: text, $2 :: bigint, $3 :: bigint, $4 :: text, $5 :: timestamptz, $6 :: timestamptz, $7 :: text, $8 :: text, $9 :: text, $10 :: text)
        )
        select
            a.id,
            a.created_at,
            a.updated_at,
            a.published_at,
            a.name,
            a.synopsis,
            a.description,
            a.kind,
            a.severity,
            a.topic,
            a.red_hat_advisory_id,
            count(a.*) over () as total
        from
            advisories a
        -- Do not join packages/cves/fixes here: that Cartesian-explodes
        -- hundreds of thousands of rows and GROUP BY then wedges list.
        -- Filters that need related tables use EXISTS below.
        where
            a.published_at is not null
"""

    where_stmt = ""

    if product:
        where_stmt += """
            and exists (select name from advisory_affected_products where advisory_id = a.id and name like '%' || (select product from vars) || '%')
        """

    if before:
        where_stmt += """
            and a.published_at < (select before from vars)
        """

    if after:
        where_stmt += """
            and a.published_at > (select after from vars)
        """

    if cve:
        if _CVE_ID.match(cve.strip()):
            where_stmt += """
            and exists (select 1 from advisory_cves where advisory_id = a.id and cve = (select cve from vars))
            """
        else:
            where_stmt += """
            and exists (select 1 from advisory_cves where advisory_id = a.id and cve ilike '%' || (select cve from vars) || '%')
            """

    if synopsis:
        where_stmt += """
            and a.synopsis ilike '%' || (select synopsis from vars) || '%'
        """

    if severity:
        where_stmt += """
            and a.severity = (select severity from vars)
        """

    if kind:
        where_stmt += """
            and a.kind = (select kind from vars)
        """

    if keyword:
        where_stmt += """
            and (
            exists (select 1 from advisory_affected_products where advisory_id = a.id and name like '%' || (select search from vars) || '%') or
            a.synopsis ilike '%' || (select search from vars) || '%' or
            a.description ilike '%' || (select search from vars) || '%' or
            exists (select cve from advisory_cves where advisory_id = a.id and cve ilike '%' || (select search from vars) || '%') or
            exists (select ticket_id from advisory_fixes where advisory_id = a.id and ticket_id ilike '%' || (select search from vars) || '%') or
            a.name ilike '%' || (select search from vars) || '%')
        """

    if require_cves:
        where_stmt += """
            and exists (select 1 from advisory_cves where advisory_id = a.id)
        """

    a += where_stmt
    a += """
        order by a.published_at desc, a.id desc
        limit (select size from vars) offset (select page_offset from vars)
    """

    connection = connections.get("default")
    results = await connection.execute_query(
        a, [
            keyword,
            size,
            page_offset,
            product,
            naive_utc(before),
            naive_utc(after),
            cve,
            synopsis,
            severity,
            kind,
        ]
    )

    count = 0
    if results:
        if results[1]:
            count = results[1][0]["total"]

    advisories = [Advisory(**x) for x in results[1]]
    if fetch_related and advisories:
        # Advisory(**row) from raw SQL is not a queryset instance;
        # per-row fetch_related("packages") can seq-scan advisory_packages
        # (~1M rows) and wedge a worker. Prefetch via filter(id__in=).
        rels = [
            "red_hat_advisory",
            "cves",
            "fixes",
            "affected_products",
        ]
        if fetch_packages:
            rels.extend(
                (
                    "packages",
                    "packages__supported_product",
                    "packages__supported_products_rh_mirror",
                )
            )
        ordered_ids = [advisory.id for advisory in advisories]
        loaded = await Advisory.filter(id__in=ordered_ids).prefetch_related(*rels)
        by_id = {advisory.id: advisory for advisory in loaded}
        advisories = [by_id[i] for i in ordered_ids if i in by_id]
    return (
        count,
        advisories,
    )
