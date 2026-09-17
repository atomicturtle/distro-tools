# RelEng updateinfo contract (Apollo → in-repo repodata)

Apollo exposes a stable updateinfo XML contract for RelEng / Peridot handoff.
Apollo does **not** own CDN publish; RelEng pulls XML and merges it into
repository `repodata/`.

## Contract (frozen)

| Item | Value |
|------|--------|
| API prefix | `/api/v3/updateinfo` |
| Preferred URL | `GET /api/v3/updateinfo/{product}/{major}/{repo}/updateinfo.xml?arch={arch}` |
| Product slugs | `rocky-linux`, `rocky-linux-sig-cloud` |
| Response | `application/xml` updateinfo document |
| Headers | `ETag` (sha256 of body), `Last-Modified`, `X-Apollo-Updateinfo-Contract: v1` |
| Scope | Package-bearing RLSAs only — no `not_shipped` / `under_investigation` |

Legacy URL (still supported):

`GET /api/v3/updateinfo/{product_name}/{repo}/updateinfo.xml?req_arch={arch}`

Example product_name: `Rocky Linux 9 x86_64`.

## Staging tree with `apollo_tree`

Pull Apollo XML into a local repository mirror for RelEng review:

```bash
python -m apollo.publishing_tools.apollo_tree \
  --path /path/to/staging/rocky/9 \
  --product-name "Rocky Linux" \
  --major-version 9 \
  --api-base https://apollo.build.resf.org/api/v3/updateinfo \
  --staging-dir /path/to/releng-handoff/rocky-9
```

`--staging-dir` copies generated `*-updateinfo.xml.gz` (and updated
`repomd.xml`) into a parallel handoff tree without mutating production CDN
paths when `--path` points at a disposable staging checkout.

## Cadence and acceptance

1. RelEng pulls on the same cadence as mirror compose (at least daily).
2. After merge, run existing `yum-gate.sh` / compose gates against the staged
   tree before promoting to the public mirror.
3. Production CDN publish remains a RelEng-owned step (external dependency).

# CSAF provider tree

Generate a Red Hat–shaped on-disk CSAF tree (SA + VEX) for mirroring:

```bash
python -m apollo.publishing_tools.csaf_tree \
  --out /var/www/apollo-csaf \
  --prefix csaf/v2 \
  --base-url https://<public-host>/csaf/v2 \
  --db-url "$APOLLO_DB_URL"
```

Produces:

```
{out}/csaf/v2/provider-metadata.json
{out}/csaf/v2/advisories/{index,changes,releases,deletions}.csv|txt
{out}/csaf/v2/advisories/{year}/rlsa-….json
{out}/csaf/v2/vex/…
```

**db1 research publish:** see [CSAF_TREE_DB1.md](CSAF_TREE_DB1.md)
(`publish-csaf-tree.sh` → `~/apollo/csaf/v2` → `/csaf/v2` on
`apollo.research.atomicorp.com`).

