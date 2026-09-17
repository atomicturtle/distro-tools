# CSAF provider tree on db1

Research publish target for the RH-shaped CSAF directory:

| Item | Value |
|------|--------|
| Host | `apollo.research.atomicorp.com` (db1) |
| On-disk tree | `~/apollo/csaf/v2/` |
| Public URL | `https://apollo.research.atomicorp.com/csaf/v2/` |
| Env | `APOLLO_CSAF_TREE`, `APOLLO_CSAF_BASE_URL` |
| Browse | Apache `Alias /csaf` + `Options +Indexes` (see `apollo/deploy/db1/errata-research.conf`) |
| Apache perms | `/home/sshinn` must be `711`; tree world-readable (`apply-csaf-apache.sh` + publish script) |
| Refresh | `apollo-csaf-publish.timer` daily ~07:00 UTC (`install-user-units.sh`) |

## One-time setup

```bash
# .env (already used by apollo.service EnvironmentFile)
APOLLO_CSAF_TREE=/home/sshinn/apollo/csaf/v2
APOLLO_CSAF_BASE_URL=https://apollo.research.atomicorp.com/csaf/v2

sudo systemctl restart apollo
~/apollo/distro-tools/apollo/deploy/db1/install-user-units.sh
# Apache indexes (needs sudo password):
~/apollo/distro-tools/apollo/deploy/db1/apply-csaf-apache.sh
```

## Generate / refresh

```bash
~/apollo/distro-tools/apollo/scripts/publish-csaf-tree.sh
# Skip archives: APOLLO_CSAF_SKIP_ARCHIVES=1 …
# Optional signing: APOLLO_CSAF_GPG_FINGERPRINT=… APOLLO_CSAF_GPG_PUBLIC_URL=…
```

## Layout

```
/csaf/v2/provider-metadata.json
/csaf/v2/advisories/{year}/*.json
/csaf/v2/advisories/{index.txt,changes.csv,releases.csv,deletions.csv}
/csaf/v2/advisories/csaf_advisories_YYYY-MM-DD.tar.zst[.sha256][.asc]
/csaf/v2/advisories/archive_latest.txt
/csaf/v2/vex/… (same shape)
```

Consumers: use `changes.csv` for incremental updates; use `archive_latest.txt` +
the pointed `.tar.zst` only for cold start (same guidance as Red Hat).

## Smoke

```bash
curl -sS https://apollo.research.atomicorp.com/csaf/v2/ | head          # HTML index after Apache apply
curl -sS https://apollo.research.atomicorp.com/csaf/v2/provider-metadata.json | head
curl -sS https://apollo.research.atomicorp.com/csaf/v2/advisories/index.txt | head
curl -sS http://127.0.0.1:8000/csaf/v2/provider-metadata.json | head   # Hypercorn fallback

# Optional validators (when installed):
#   csaf validate /path/to/rlsa-….json
#   oscap oval eval --results /tmp/r.xml org.rockylinux.rlsa-9.xml
```

## Related APIs

| Feed | Endpoint | Notes |
|------|----------|--------|
| Bulk errata.json | `/api/v3/bulk/rocky-linux/{major}/errata.json` | Full dump; EL9 is ~100MB+ — prefer streaming/`curl -OJ` |
| CSAF SA API | `/api/v3/csaf/advisories/{RLSA}` | Live generate |
| CSAF VEX API | `/api/v3/csaf/vex/{CVE}` | Live generate |
| OpenVEX | `/api/v3/vex/cves/{CVE}` | |
| OVAL | `/api/v3/oval/rocky-linux/{major}` | |
