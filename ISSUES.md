# Open issues — db1 Apollo

On `deploy/db1` (atomicturtle fork only). Not for a resf PR.

IDs are stable (1–5 and **15** finished, dropped; **13** and **14** parked). **Bug** = wrong or incomplete catalog/API vs what this host already publishes. **Feature** = a surface or feed Apollo does not emit today.

## Bugs

17. **Bug** — Same thinning as **15**, leftover clones. Matcher is fixed (`fbcef7e` / `757d838`); **71** RLSAs still have no ship-arch RPMs while the RH donor does (43 `nodejs`, also `idm` / `php` / `maven` / `eclipse`, plus 18 non-modular). Example: `RLSA-2024:5814` is 5 noarch vs RH 24 binaries. Needs targeted rematch with `--include-historical --replace-packages`, not more matcher work. Do not rematch the whole 554 set.

## Features

6. **Done** — CSAF Security Advisory files. `GET /api/v3/csaf/advisories/{RLSA}`, index, `provider-metadata.json`, `changes.csv`. Generator in `apollo/exports/csaf_sa.py` (CEM rocky_clone port, Rocky publisher / RLSA ids). Tree writer: `apollo/publishing_tools/csaf_tree.py`.

7. **Done** — CSAF VEX files. `GET /api/v3/csaf/vex/{CVE}` from `CveProductStatus`; OpenVEX hardened at `GET /api/v3/vex/cves/{CVE}` with `pkg:rpm/rockylinux` PURLs for fixed statuses.

8. **Done** — OVAL for Rocky 8/9/10. `GET /api/v3/oval/rocky-linux/{major}` (`org.rockylinux.rlsa-{N}.xml`, optional gzip).

9. **Done** — Bulk dump. `GET /api/v3/bulk/rocky-linux/{major}/errata.json` (full non-paginated array).

10. **Done (Apollo side)** — RelEng updateinfo contract. ETag / Last-Modified / `X-Apollo-Updateinfo-Contract: v1` on `/api/v3/updateinfo`. Staging handoff via `apollo_tree --staging-dir`. See [docs/RELENG_UPDATEINFO.md](docs/RELENG_UPDATEINFO.md). CDN publish remains RelEng-owned.

11. **Feature** — In-document CPE on CRLSA OS products. Sidecar `cpe-product-keys.json` only. CIQSA already embeds CPE. CIQ transform, not Apollo.

12. **Feature** — CPE 2.3 string shape. Host `system-release-cpe` is truncated (`…:9.8`); some CSAF/STIG docs use full wildcards. String equality fails. RelEng / platform, not Apollo.

16. **Mitigated** — Catalog cadence. `apollo-catalog.timer` runs every **6 hours** (`OnCalendar=*-*-* 00,06,12,18:00:00 UTC`). Residual gap is same-window lag (up to ~6h), not once-daily. Continuous/event-driven ingest is still optional. Do not use `sync-full.sh`.

## Parked

13. **Parked** — `RLSA-2022:7318` x86_64-only. Production is Rocky **9.0 Legacy** kernel (`5.14.0-70.30.1.el9_0`). db1 has 24 x86_64 + 2 noarch. Snapshot EVR pin will not attach other-arch 9.0 RPMs from current or vault 9.7. Also stamps `Rocky Linux 9 aarch64` with zero aarch64 RPMs (noarch inherited the walked stream arch). One-off vault-9.0 rematch could restore other arches; not worth a matcher change.

14. **Parked** — EL8 ppc64le / s390x packages. Public `dl.rockylinux.org` has **no** `os/repomd` for those arches on vault 8.3–8.9 **or** current 8 / 8.10 (404). EL8 aarch64 vault exists; EL9 has all four arches. Matcher cannot clone NEVRAs that are not in any indexed XML. Needs RelEng or another RPM tree; not an Apollo fix. Empty mirror rows (0 repomds) are leftover from `add_vault_mirrors.py`.
