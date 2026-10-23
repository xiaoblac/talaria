#!/usr/bin/env bash
# Server-side collector for refuzz-perf replay runs.
#
# Usage:
#   bash docker/collect_perf_results.sh --results /data/perf-results [--no-wait]
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/collect_perf_results.py" "$@"
