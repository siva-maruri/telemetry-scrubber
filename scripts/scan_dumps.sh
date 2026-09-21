#!/usr/bin/env bash
# Scan a folder of JSON-lines telemetry dumps and report what would be scrubbed.
# Handy before replaying old exports into a new backend.
#
#   bash scripts/scan_dumps.sh ./dumps            # summary per file
#   bash scripts/scan_dumps.sh ./dumps ./clean    # also write scrubbed copies

set -euo pipefail

src_dir="${1:?usage: scan_dumps.sh <dump_dir> [out_dir]}"
out_dir="${2:-}"

if [[ ! -d "$src_dir" ]]; then
  echo "not a directory: $src_dir" >&2
  exit 1
fi
[[ -n "$out_dir" ]] && mkdir -p "$out_dir"

shopt -s nullglob
files=("$src_dir"/*.jsonl)
if (( ${#files[@]} == 0 )); then
  echo "no .jsonl files in $src_dir" >&2
  exit 1
fi

for f in "${files[@]}"; do
  echo "== $(basename "$f")"
  if [[ -n "$out_dir" ]]; then
    python -m telemetry_scrubber "$f" > "$out_dir/$(basename "$f")"
  else
    python -m telemetry_scrubber --summary-only "$f"
  fi
done 2>&1
