#!/usr/bin/env bash
# Cross-agent compatibility test: an agent such as OpenCode loads the skill from
# its own skills directory and does not export CLAUDE_PLUGIN_ROOT. Copy the skill
# elsewhere, unset that variable, and run the normal integration assertions.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

test -f "$ROOT/.opencode/skills/elixir-security-audit/SKILL.md" || {
  echo "FAIL: .opencode/skills/elixir-security-audit symlink is broken"
  exit 1
}
echo "ok   .opencode/skills discovery path"

cp -R "$ROOT/skills/elixir-security-audit" "$TMP/elixir-security-audit"
test -f "$TMP/elixir-security-audit/SKILL.md" || {
  echo "FAIL: copied skill has no SKILL.md"
  exit 1
}

SKILL_DIR="$TMP/elixir-security-audit" env -u CLAUDE_PLUGIN_ROOT \
  bash "$ROOT/test/run.sh" "$@"
