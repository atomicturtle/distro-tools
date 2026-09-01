# Open issues — db1 Apollo

On `deploy/db1` (atomicturtle fork only). Not for a resf PR.

IDs are stable (1–5 and **15** finished, dropped; **13** and **14** parked). **Bug** = wrong or incomplete catalog/API vs what this host already publishes. **Feature** = a surface or feed Apollo does not emit today.

## Bugs

17. **Bug** — Same thinning as **15**, leftover clones. Matcher is fixed (`fbcef7e` / `757d838`); **71** RLSAs still have no ship-arch RPMs while the RH donor does (43 `nodejs`, also `idm` / `php` / `maven` / `eclipse`, plus 18 non-modular). Example: `RLSA-2024:5814` is 5 noarch vs RH 24 binaries. Needs targeted rematch with `--include-historical --replace-packages`, not more matcher work. Do not rematch the whole 554 set.

## Features

6. **Feature** — CSAF Security Advisory files. Apollo consumes RH CSAF; it does not emit SA documents. Scanners that only subscribe to CSAF get nothing from this host. Rocky-from-CIQ `CRLSA` is a transform of Apollo and lags. Needs a generator plus a way to subscribe (get-by-id API vs provider tree). Not RelEng `updateinfo` (**#10**), not VEX (**#7**).

7. **Feature** — CSAF VEX files. Separate generator from **#6**. CIQ VEX is LTS / FIPS / Bridge only. Docs that point Rocky-from-CIQ scanners at VEX 404.

8. **Feature** — Current OVAL for Rocky 8/9/10. `dl.rockylinux.org/pub/oval/` is a 2024 snapshot; no Rocky 10 file; generator archived. OpenSCAP users miss 2025/2026 RLSAs. Not an Apollo endpoint today.

9. **Feature** — Bulk dump. Paginated JSON only. No Alma-style `errata.full.json` or CSAF index.

10. **Feature** — RelEng in-repo `updateinfo.xml` from this catalog. `dnf` / Trivy / Foreman do not see Apollo’s XML until RelEng publishes. Repo XML lags (same-day nginx RLSA missing from Rocky 10 AppStream at probe).

11. **Feature** — In-document CPE on CRLSA OS products. Sidecar `cpe-product-keys.json` only. CIQSA already embeds CPE. CIQ transform, not Apollo.

12. **Feature** — CPE 2.3 string shape. Host `system-release-cpe` is truncated (`…:9.8`); some CSAF/STIG docs use full wildcards. String equality fails. RelEng / platform, not Apollo.

16. **Feature** — Same-day catalog vs production. Daily timer is **06:00 UTC**. Production RLSAs published later that day 404 on db1 until a manual `start-catalog.sh`. Incremental CSAF+Hydra+rematch does catch up; it is not continuous. Do not use `sync-full.sh`.

## Parked

13. **Parked** — `RLSA-2022:7318` x86_64-only. Production is Rocky **9.0 Legacy** kernel (`5.14.0-70.30.1.el9_0`). db1 has 24 x86_64 + 2 noarch. Snapshot EVR pin will not attach other-arch 9.0 RPMs from current or vault 9.7. Also stamps `Rocky Linux 9 aarch64` with zero aarch64 RPMs (noarch inherited the walked stream arch). One-off vault-9.0 rematch could restore other arches; not worth a matcher change.

14. **Parked** — EL8 ppc64le / s390x packages. Public `dl.rockylinux.org` has **no** `os/repomd` for those arches on vault 8.3–8.9 **or** current 8 / 8.10 (404). EL8 aarch64 vault exists; EL9 has all four arches. Matcher cannot clone NEVRAs that are not in any indexed XML. Needs RelEng or another RPM tree; not an Apollo fix. Empty mirror rows (0 repomds) are leftover from `add_vault_mirrors.py`.
