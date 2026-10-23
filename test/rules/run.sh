#!/usr/bin/env bash
# Rule tests for skills/elixir-security-audit/rules/elixir-security.yml.
#   1. `opengrep test` on each annotated target (+ elixir-security.fixed.ex fixtest)
#   2. a real scan to check `paths:` filters, which `opengrep test` ignores
# Usage: test/rules/run.sh   (OPENGREP=/path/to/opengrep to override)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RULES="$ROOT/skills/elixir-security-audit/rules/elixir-security.yml"
OPENGREP="${OPENGREP:-$(command -v opengrep || true)}"
if [ -z "$OPENGREP" ]; then
  echo "opengrep not found (Semgrep OSS skips Elixir rules; see test/rules/README.md)" >&2
  exit 1
fi

fail=0

"$OPENGREP" validate "$RULES" >/dev/null 2>&1 || { echo "FAIL validate"; fail=1; }

# Only targets whose annotations do not depend on `paths:` filters.
for t in elixir-security.ex config/prod.exs templates/profile.html.heex; do
  if out="$("$OPENGREP" test --config "$RULES" "$ROOT/test/rules/$t" 2>&1)"; then
    echo "ok   test $t"
  else
    echo "FAIL test $t"; grep -i "fail" <<<"$out" | sed 's/^/  /'; fail=1
  fi
done

# paths: checks — scan from inside test/rules (opengrep ignores test/ paths
# relative to the git root otherwise).
json="$(cd "$ROOT/test/rules" && "$OPENGREP" scan --config "$RULES" --json . 2>/dev/null)"
check() { # <description> <python expression over list `r` of (rule, path)>
  if python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
r = [(x['check_id'].rsplit('.', 1)[-1], x['path'].lstrip('./')) for x in d['results']]
sys.exit(0 if ($2) else 1)" <<<"$json"; then
    echo "ok   paths $1"
  else
    echo "FAIL paths $1"; fail=1
  fi
}
check "exs-cfg-001 skips dev.exs" "('exs-cfg-001', 'config/dev.exs') not in r and ('exs-cfg-001', 'config/prod.exs') in r"
check "exs-cfg-001-salt only prod/runtime" "all(p.endswith(('prod.exs', 'runtime.exs')) for i, p in r if i == 'exs-cfg-001-salt')"
check "exs-xss-001-template only templates" "all(p.endswith(('.heex', '.eex', '.leex')) for i, p in r if i == 'exs-xss-001-template') and any(i == 'exs-xss-001-template' for i, _ in r)"

exit "$fail"
