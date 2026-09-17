#!/usr/bin/env bash
# Apply errata-research.conf CSAF Alias+Indexes (requires sudo).
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)/errata-research.conf"
DST=/etc/httpd/conf.d/errata-research.conf
[[ -f "$SRC" ]] || { echo "missing $SRC"; exit 1; }
sudo cp -a "$DST" "${DST}.bak.$(date +%Y%m%d%H%M%S)"
sudo cp "$SRC" "$DST"
sudo apachectl configtest
sudo systemctl reload httpd
echo "Applied $DST and reloaded httpd"
curl -sS -o /dev/null -w "browse=%{http_code}\n" https://apollo.research.atomicorp.com/csaf/v2/ || true
curl -sS -o /dev/null -w "meta=%{http_code}\n" https://apollo.research.atomicorp.com/csaf/v2/provider-metadata.json || true
