#!/usr/bin/env bash
# verify-decisions.sh — check an export of edge-egress's decision log (B28.228).
#
# The control plane's GET /admin/v1/decisions returns the log as NDJSON, one
# record per line. Each record names, as prev, the sha256 of the line before it
# (the first record of the log names 64 zeros), and its seq is one more than the
# line before. This checks every link, then prints how many records it read and
# the hash of the last line: the head. Keep the head. A later export holding the
# line with that hash, still linked to everything after it, shows that nothing
# up to it was changed, removed or reordered.
#
# Usage:  scripts/verify-decisions.sh [FILE]      (default: stdin)
# Needs:  jq, and sha256sum or shasum.
# Exit:   0 and "verified: …" when every link holds; 1 naming the first line
#         that breaks the chain.
set -euo pipefail

GENESIS=0000000000000000000000000000000000000000000000000000000000000000

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1
}
broken() { echo "verify-decisions: line $1: $2" >&2; exit 1; }

n=0 first="" seq="" prev="" start=""
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  fields="$(jq -r '"\(.seq) \(.prev)"' <<<"$line" 2>/dev/null)" || broken "$n" "not a JSON record"
  s="${fields%% *}" p="${fields#* }"
  case "$s" in '' | *[!0-9]*) broken "$n" "no seq" ;; esac
  if [ "$n" = 1 ]; then
    # An export from ?after=N starts at seq N+1, linked to record N's hash.
    [ "$s" != 1 ] || [ "$p" = "$GENESIS" ] || broken 1 "record 1 does not start the log (prev $p)"
    first="$s" start="$p"
  else
    [ "$s" = $((seq + 1)) ] || broken "$n" "seq $s does not follow $seq"
    [ "$p" = "$prev" ] || broken "$n" "seq $s names prev $p, but the line before it hashes to $prev"
  fi
  seq="$s"
  prev="$(printf '%s' "$line" | sha256)"
done < "${1:-/dev/stdin}"

[ "$n" -gt 0 ] || { echo "verify-decisions: no records" >&2; exit 1; }
echo "verified: $n records, seq $first..$seq, chained to $start, head $prev"
