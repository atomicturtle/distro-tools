# NVD enrichment — branch map

| Branch | Purpose | Push to resf? |
| --- | --- | --- |
| `feature/nvd-cve-enrichment` | NVD schema + sync + `GET /api/v3/nvd/cves/{id}` from `origin/main` | Yes (when ready) |
| `deploy/db1-nvd` | db1 checkout tip: `deploy/db1` matcher stack **plus** NVD commits | **Never** |
| `deploy/db1` | Matcher research only — no NVD | **Never** |

RH `advisory_cves` scores stay authoritative. `nvd_cves` is the NIST join (CVSS v2/v3/v4, CWE, refs).

```bash
# Sync a batch (API key recommended):
PYTHONPATH=. python -m apollo.nvd.cli --only-missing --limit 50
```
