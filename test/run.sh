#!/usr/bin/env bash
# Integration test: scan the vulnerable fixture and assert the expected EXS ids are found.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$ROOT/test/fixtures/vulnerable_app"
SCAN="$ROOT/skills/elixir-security-audit/scripts/scan.sh"
EXPECTED="$ROOT/test/fixtures/expected_findings.txt"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

(cd "$FIXTURE" && mix deps.get >/dev/null)
bash "$SCAN" "$FIXTURE" --out "$OUT" "$@"

test -s "$OUT/findings.json" || { echo "FAIL: findings.json missing"; exit 1; }
test -s "$OUT/summary.md" || { echo "FAIL: summary.md missing"; exit 1; }

found="$(python3 -I -c 'import json,sys; print("\n".join(sorted({f["id"] for f in json.load(open(sys.argv[1]))})))' "$OUT/findings.json")"
missing=0
while IFS= read -r id; do
  case "$id" in ''|\#*) continue ;; esac
  if printf '%s\n' "$found" | grep -qx "$id"; then
    echo "ok   $id"
  else
    echo "MISS $id"; missing=$((missing + 1))
  fi
done < "$EXPECTED"

[ "$missing" -eq 0 ] || { echo "FAIL: $missing expected finding(s) missing"; exit 1; }
echo "PASS: all expected findings detected"
