# NVD enrichment — branch map

| Branch | Purpose | Push to resf? |
| --- | --- | --- |
| `feature/nvd-cve-enrichment` | NVD schema + sync + `GET /api/v3/nvd/cves/{id}` from `origin/main` | Yes (when ready) |
| `deploy/db1-nvd` | db1 checkout tip: `deploy/db1` matcher stack **plus** NVD commits | **Never** |
| `deploy/db1` | Matcher research only — no NVD | **Never** |

RH `advisory_cves` scores stay authoritative. `nvd_cves` is the NVD/vuls.db join
(CVSS v2/v3/v4, CWE, refs, **EPSS**, **KEV**, **exploit maturity**, sample **CPEs**).

**Prototype source:** local `vuls.db` (vuls2 BoltDB), not the NIST REST API.

Note: the Atomic slim `vuls.db` currently includes CISA/VulnCheck **KEV** and NVD CPE
detections, but does **not** ship the `epss` datasource — `epss_score` will stay null
until that feed is added (or we wire FIRST.org separately).

```bash
# Build helper (Fedora workstation):
cd apollo/nvd/vulsdb_export
GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -o vulsdb-nvd-export .

# On db1 (binary + code already deployed):
source ~/apollo/.env
cd ~/apollo/distro-tools
ENV=production DB_USER=apollo \
  PYTHONPATH=. ~/apollo/venv/bin/python -m apollo.nvd.cli \
  --from-vuls-db
```

NIST API path remains available without `--from-vuls-db` (slow; needs `NVD_API_KEY`).
