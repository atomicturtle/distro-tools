#!/usr/bin/env bash
# Publish Apollo CSAF SA+VEX tree for db1 research host.
#
# Writes an RH-shaped tree under APOLLO_CSAF_TREE, builds tar.zst archives,
# and serves via Apache Alias /csaf (preferred) or Hypercorn StaticFiles.
#
# Usage (on db1):
#   ~/apollo/distro-tools/apollo/scripts/publish-csaf-tree.sh

set -euo pipefail

APOLLO_HOME="${APOLLO_HOME:-$HOME/apollo}"
REPO="${APOLLO_REPO:-$APOLLO_HOME/distro-tools}"
ENV_FILE="${APOLLO_ENV_FILE:-$APOLLO_HOME/.env}"
OUT="${APOLLO_CSAF_TREE:-$APOLLO_HOME/csaf/v2}"
BASE_URL="${APOLLO_CSAF_BASE_URL:-https://apollo.research.atomicorp.com/csaf/v2}"
PYTHON="${APOLLO_PYTHON:-$APOLLO_HOME/venv/bin/python}"
SKIP_ARCHIVES="${APOLLO_CSAF_SKIP_ARCHIVES:-0}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

export ENV="${ENV:-production}"
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-5432}"
export DB_USER="${DB_USER:-apollo}"
export DB_SSLMODE="${DB_SSLMODE:-disable}"
export APOLLO_CSAF_BASE_URL="$BASE_URL"

cd "$REPO"

DB_URL="$("$PYTHON" - <<'PY'
from common.info import Info
from common.database import Database
Info("apollo2")
print(Database(True, None, ["apollo.db"]).conn_str())
PY
)"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/apollo-csaf.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

echo "Generating CSAF tree -> $STAGE (base-url=$BASE_URL)"
PYTHONPATH=. "$PYTHON" -m apollo.publishing_tools.csaf_tree \
  --out "$STAGE" \
  --db-url "$DB_URL" \
  --base-url "$BASE_URL"

if [[ "$SKIP_ARCHIVES" != "1" ]]; then
  echo "Building RH-shaped archives under $STAGE"
  PYTHONPATH=. "$PYTHON" - <<PY
from apollo.publishing_tools.csaf_archives import build_provider_archives
print(build_provider_archives("$STAGE"))
PY
fi

mkdir -p "$OUT"
# Atomic-ish swap: rsync into place so readers never see an empty tree.
rsync -a --delete "$STAGE"/ "$OUT"/

ADV_COUNT="$(find "$OUT/advisories" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
VEX_COUNT="$(find "$OUT/vex" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
echo "Published $OUT"
echo "  advisories: $ADV_COUNT"
echo "  vex:        $VEX_COUNT"
echo "  provider:   $OUT/provider-metadata.json"
if [[ -f "$OUT/advisories/archive_latest.txt" ]]; then
  echo "  adv archive: $(cat "$OUT/advisories/archive_latest.txt")"
fi
if [[ -f "$OUT/vex/archive_latest.txt" ]]; then
  echo "  vex archive: $(cat "$OUT/vex/archive_latest.txt")"
fi
echo "URL: $BASE_URL/provider-metadata.json"
