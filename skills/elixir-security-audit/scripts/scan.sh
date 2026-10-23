#!/usr/bin/env bash
# elixir-security-audit: scan.sh
#
# Elixir/Phoenix 프로젝트에 Elixir 전용 보안 도구(mix hex.audit, mix_audit, Sobelow)와
# 선택 도구(osv-scanner, semgrep/opengrep)를 실행하고, grep 기반 패턴 보완 검사를 더한 뒤
# summarize.py 로 findings.json / summary.md 를 만든다.
#
# Runs Elixir-specific security tools plus a grep supplement and normalizes results.
# Portable: macOS bash 3.2 / BSD userland and Linux GNU userland.
#
# Exit codes: 0 = scan finished (findings or not), 1 = execution error, 2 = not an Elixir project.

set -uo pipefail

usage() {
  cat <<'EOF'
Usage: scan.sh [OPTIONS] [PROJECT_DIR]

Scan an Elixir/Phoenix project and write results to PROJECT_DIR/security-audit/.

Options:
  --no-deps-fetch   Do not run `mix deps.get` before scanning
  --skip-semgrep    Do not run semgrep/opengrep even if installed
  --out DIR         Output directory (default: PROJECT_DIR/security-audit)
  -h, --help        Show this help

Outputs: hex-audit.txt, deps-audit.json, sobelow.json, osv.json, semgrep.json,
         grep.txt, tools.txt, findings.json, summary.md
Exit codes: 0 = scan finished, 1 = execution error, 2 = not an Elixir project
EOF
}

warn() { printf '[scan] WARN: %s\n' "$*" >&2; }
info() { printf '[scan] %s\n' "$*" >&2; }

PROJECT_DIR=""
OUT_DIR=""
DEPS_FETCH=1
RUN_SEMGREP=1

while [ $# -gt 0 ]; do
  case "$1" in
    --no-deps-fetch) DEPS_FETCH=0 ;;
    --skip-semgrep) RUN_SEMGREP=0 ;;
    --out)
      if [ $# -lt 2 ]; then warn "--out requires a directory"; exit 1; fi
      OUT_DIR="$2"; shift ;;
    --out=*) OUT_DIR="${1#--out=}" ;;
    -h|--help) usage; exit 0 ;;
    -*) warn "unknown option: $1"; usage >&2; exit 1 ;;
    *)
      if [ -n "$PROJECT_DIR" ]; then warn "only one PROJECT_DIR allowed"; exit 1; fi
      PROJECT_DIR="$1" ;;
  esac
  shift
done

[ -n "$PROJECT_DIR" ] || PROJECT_DIR="."

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd) || { warn "cannot resolve script dir"; exit 1; }

if [ ! -d "$PROJECT_DIR" ]; then
  warn "not a directory: $PROJECT_DIR"
  exit 2
fi
PROJECT_DIR=$(cd "$PROJECT_DIR" && pwd) || exit 1

if [ ! -f "$PROJECT_DIR/mix.exs" ]; then
  warn "no mix.exs in $PROJECT_DIR - not an Elixir project"
  exit 2
fi

[ -n "$OUT_DIR" ] || OUT_DIR="$PROJECT_DIR/security-audit"
mkdir -p "$OUT_DIR" || { warn "cannot create output dir: $OUT_DIR"; exit 1; }
OUT_DIR=$(cd "$OUT_DIR" && pwd) || exit 1

TOOLS_FILE="$OUT_DIR/tools.txt"
GREP_FILE="$OUT_DIR/grep.txt"
: > "$TOOLS_FILE" || { warn "cannot write to $OUT_DIR"; exit 1; }
: > "$GREP_FILE"

# Remove stale raw outputs from a previous run so summarize.py never mixes runs.
rm -f "$OUT_DIR/hex-audit.txt" "$OUT_DIR/deps-audit.json" "$OUT_DIR"/sobelow*.json \
      "$OUT_DIR/osv.json" "$OUT_DIR/semgrep.json" "$OUT_DIR/findings.json" "$OUT_DIR/summary.md"

# tool_status NAME STATUS NOTE  (STATUS: ran | skipped | failed)
tool_status() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TOOLS_FILE"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Run a command inside the project directory.
in_project() { (cd "$PROJECT_DIR" && "$@"); }

# ---------------------------------------------------------------------------
# Project layout
# ---------------------------------------------------------------------------

UMBRELLA=0
if grep -Eq 'apps_path[[:space:]]*:' "$PROJECT_DIR/mix.exs"; then
  UMBRELLA=1
fi

# Relative source/config directories (space-free names expected for Mix apps).
LIB_DIRS=""
CONFIG_DIRS=""
APP_DIRS=""
[ -d "$PROJECT_DIR/lib" ] && LIB_DIRS="lib"
[ -d "$PROJECT_DIR/config" ] && CONFIG_DIRS="config"
if [ -d "$PROJECT_DIR/apps" ]; then
  for d in "$PROJECT_DIR"/apps/*; do
    [ -f "$d/mix.exs" ] || continue
    app="apps/$(basename "$d")"
    APP_DIRS="$APP_DIRS $app"
    [ -d "$d/lib" ] && LIB_DIRS="$LIB_DIRS $app/lib"
    [ -d "$d/config" ] && CONFIG_DIRS="$CONFIG_DIRS $app/config"
  done
fi
# grep also covers priv/ (migrations, seeds, uncompiled examples with raw SQL).
SRC_DIRS="$LIB_DIRS"
for d in priv $(for a in $APP_DIRS; do echo "$a/priv"; done); do
  [ -d "$PROJECT_DIR/$d" ] && SRC_DIRS="$SRC_DIRS $d"
done

info "project: $PROJECT_DIR (umbrella=$UMBRELLA)"
info "output:  $OUT_DIR"

HAVE_MIX=0
if have mix; then HAVE_MIX=1; else warn "mix not found - skipping all mix-based tools"; fi

# ---------------------------------------------------------------------------
# 1. mix deps.get
# ---------------------------------------------------------------------------

if [ $HAVE_MIX -eq 1 ] && [ $DEPS_FETCH -eq 1 ]; then
  info "mix deps.get"
  if ! in_project mix deps.get > "$OUT_DIR/deps-get.log" 2>&1; then
    warn "mix deps.get failed (see deps-get.log) - continuing"
  fi
fi

# mix_task_available TASK DEP : true if TASK is runnable in the project, either
# because `mix help TASK` succeeds (archive or compiled dep) or because DEP is
# declared in a mix.exs and fetched into deps/ (mix compiles it on first run).
mix_task_available() {
  [ $HAVE_MIX -eq 1 ] || return 1
  in_project mix help "$1" >/dev/null 2>&1 && return 0
  for mf in mix.exs $(for a in $APP_DIRS; do echo "$a/mix.exs"; done); do
    if grep -Eq "\{:$2[[:space:]]*," "$PROJECT_DIR/$mf" 2>/dev/null; then
      [ -d "$PROJECT_DIR/deps/$2" ] && return 0
      warn "$2 is declared in $mf but not fetched (run mix deps.get or drop --no-deps-fetch)"
      return 1
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# 2. mix hex.audit  (retired packages)
# ---------------------------------------------------------------------------

if [ $HAVE_MIX -eq 1 ]; then
  info "mix hex.audit"
  in_project mix hex.audit > "$OUT_DIR/hex-audit.txt" 2>&1
  rc=$?
  # Exit 1 means retired packages (and, on newer Hex, security advisories) found.
  if [ $rc -eq 0 ]; then
    tool_status hex_audit ran "no retired packages / advisories"
  elif grep -Eqi 'retired|advisor' "$OUT_DIR/hex-audit.txt"; then
    tool_status hex_audit ran "retired packages or advisories found"
  else
    warn "mix hex.audit failed (exit $rc) - see hex-audit.txt"
    tool_status hex_audit failed "exit $rc"
  fi
else
  tool_status hex_audit skipped "mix not found"
fi

# ---------------------------------------------------------------------------
# 3. mix deps.audit (mix_audit)
# ---------------------------------------------------------------------------

if mix_task_available deps.audit mix_audit; then
  info "mix deps.audit --format json"
  in_project mix deps.audit --format json > "$OUT_DIR/deps-audit.json" 2> "$OUT_DIR/deps-audit.log"
  rc=$?
  # mix_audit exits non-zero when vulnerabilities are found; JSON is still written.
  if grep -q '"pass"' "$OUT_DIR/deps-audit.json" 2>/dev/null; then
    tool_status mix_audit ran "exit $rc"
  else
    warn "mix deps.audit produced no JSON (exit $rc) - see deps-audit.log"
    tool_status mix_audit failed "exit $rc"
  fi
elif have mix_audit; then
  info "mix_audit --format json (escript)"
  in_project mix_audit --format json > "$OUT_DIR/deps-audit.json" 2> "$OUT_DIR/deps-audit.log"
  rc=$?
  if grep -q '"pass"' "$OUT_DIR/deps-audit.json" 2>/dev/null; then
    tool_status mix_audit ran "escript, exit $rc"
  else
    warn "mix_audit produced no JSON (exit $rc)"
    tool_status mix_audit failed "escript, exit $rc"
  fi
else
  warn "mix_audit not available - add {:mix_audit, \"~> 2.1\", only: [:dev, :test], runtime: false}"
  tool_status mix_audit skipped "mix_audit not in deps"
fi

# ---------------------------------------------------------------------------
# 4. Sobelow
# ---------------------------------------------------------------------------

# run_sobelow ROOT OUTFILE : ROOT is relative to project ("" = project root).
run_sobelow() {
  root="$1"; outfile="$2"
  log="${outfile%.json}.log"
  rm -f "$outfile"
  if [ -n "$root" ]; then
    in_project mix sobelow --root "$root" --format json --out "$outfile" > "$log" 2>&1
  else
    in_project mix sobelow --format json --out "$outfile" > "$log" 2>&1
  fi
  rc=$?
  # Older Sobelow versions ignore --out for json; fall back to captured stdout.
  if [ ! -s "$outfile" ] && grep -q '"findings"' "$log" 2>/dev/null; then
    cp "$log" "$outfile"
  fi
  [ -s "$outfile" ] || return 1
  return 0
}

if mix_task_available sobelow sobelow; then
  if [ $UMBRELLA -eq 1 ] && [ -n "$APP_DIRS" ]; then
    ok=0; total=0
    for app in $APP_DIRS; do
      total=$((total + 1))
      name=$(basename "$app")
      info "mix sobelow --root $app"
      if run_sobelow "$app" "$OUT_DIR/sobelow-$name.json"; then
        ok=$((ok + 1))
      else
        warn "sobelow failed for $app (see sobelow-$name.log)"
      fi
    done
    if [ $ok -gt 0 ]; then
      tool_status sobelow ran "umbrella: $ok/$total apps"
    else
      tool_status sobelow failed "umbrella: 0/$total apps"
    fi
  else
    info "mix sobelow --format json"
    if run_sobelow "" "$OUT_DIR/sobelow.json"; then
      tool_status sobelow ran ""
    else
      warn "sobelow failed (see sobelow.log)"
      tool_status sobelow failed "see sobelow.log"
    fi
  fi
else
  warn "sobelow not available - add {:sobelow, \"~> 0.13\", only: [:dev, :test], runtime: false}"
  tool_status sobelow skipped "sobelow not in deps"
fi

# ---------------------------------------------------------------------------
# 5. osv-scanner (optional)
# ---------------------------------------------------------------------------

if have osv-scanner; then
  info "osv-scanner"
  # v2 syntax first, then v1 syntax.
  osv-scanner scan source -r "$PROJECT_DIR" --format json > "$OUT_DIR/osv.json" 2> "$OUT_DIR/osv.log"
  rc=$?
  if ! grep -q '"results"' "$OUT_DIR/osv.json" 2>/dev/null; then
    osv-scanner -r "$PROJECT_DIR" --format json > "$OUT_DIR/osv.json" 2>> "$OUT_DIR/osv.log"
    rc=$?
  fi
  # osv-scanner exits 1 when vulnerabilities are found.
  if grep -q '"results"' "$OUT_DIR/osv.json" 2>/dev/null; then
    tool_status osv ran "exit $rc"
  else
    warn "osv-scanner produced no JSON (exit $rc) - see osv.log"
    rm -f "$OUT_DIR/osv.json"
    tool_status osv failed "exit $rc"
  fi
else
  tool_status osv skipped "osv-scanner not installed"
fi

# ---------------------------------------------------------------------------
# 6. semgrep / opengrep (optional)
# ---------------------------------------------------------------------------

RULES_FILE="$SCRIPT_DIR/../rules/elixir-security.yml"
if [ $RUN_SEMGREP -eq 0 ]; then
  tool_status semgrep skipped "--skip-semgrep"
elif [ ! -f "$RULES_FILE" ]; then
  warn "rules file not found: $RULES_FILE"
  tool_status semgrep skipped "rules file missing"
else
  # Semgrep OSS silently skips `languages: [elixir]` rules (Pro only), so prefer
  # opengrep; use semgrep only with --pro. Both run from inside the project dir,
  # because the default .semgrepignore drops test/ paths relative to the git root.
  OG="${OPENGREP_BIN:-opengrep}"
  SG_EXCLUDES="--exclude deps --exclude _build --exclude security-audit --exclude node_modules"
  if have "$OG"; then
    info "opengrep --config elixir-security.yml"
    # shellcheck disable=SC2086
    in_project "$OG" scan --config "$RULES_FILE" --json --quiet $SG_EXCLUDES \
      -o "$OUT_DIR/semgrep.json" . > "$OUT_DIR/semgrep.log" 2>&1
    rc=$?
    SG=opengrep
  elif have semgrep; then
    info "semgrep --pro --config elixir-security.yml"
    # shellcheck disable=SC2086
    in_project semgrep scan --pro --config "$RULES_FILE" --json --metrics=off --quiet $SG_EXCLUDES \
      -o "$OUT_DIR/semgrep.json" . > "$OUT_DIR/semgrep.log" 2>&1
    rc=$?
    SG="semgrep --pro"
  else
    SG=""
  fi
  if [ -z "$SG" ]; then
    tool_status semgrep skipped "opengrep not installed"
  elif grep -q '"results"' "$OUT_DIR/semgrep.json" 2>/dev/null; then
    tool_status semgrep ran "$SG, exit $rc"
  elif [ "$SG" != opengrep ]; then
    warn "semgrep --pro unavailable; Semgrep OSS does not run Elixir rules - install opengrep"
    rm -f "$OUT_DIR/semgrep.json"
    tool_status semgrep skipped "Semgrep OSS skips Elixir rules (needs --pro); install opengrep"
  else
    warn "opengrep produced no JSON (exit $rc) - see semgrep.log"
    rm -f "$OUT_DIR/semgrep.json"
    tool_status semgrep failed "opengrep, exit $rc"
  fi
fi

# ---------------------------------------------------------------------------
# 7. grep supplement
# ---------------------------------------------------------------------------

# Convert `file:line:content` from grep into `ID<TAB>file<TAB>line<TAB>snippet`,
# dropping comment-only lines.
to_tsv() {
  awk -v id="$1" '
    {
      i = index($0, ":"); if (i == 0) next
      f = substr($0, 1, i - 1); r = substr($0, i + 1)
      j = index(r, ":"); if (j == 0) next
      l = substr(r, 1, j - 1); s = substr(r, j + 1)
      if (l !~ /^[0-9]+$/) next
      gsub(/\t/, " ", s); gsub(/\r/, "", s)
      sub(/^[ ]+/, "", s); sub(/[ ]+$/, "", s)
      if (s ~ /^#/ || s ~ /^<%#/ || s ~ /^<%!--/) next
      if (length(s) > 200) s = substr(s, 1, 200) "..."
      printf "%s\t%s\t%s\t%s\n", id, f, l, s
    }'
}

# grep_src ID REGEX EXCLUDE [INCLUDE_GLOB...] : grep the source dirs for REGEX,
# dropping lines that match EXCLUDE (empty = keep all).
grep_src() {
  id="$1"; re="$2"; excl="$3"; shift 3
  [ -n "$SRC_DIRS" ] || return 0
  inc=""
  if [ $# -eq 0 ]; then set -- '*.ex' '*.exs'; fi
  for g in "$@"; do inc="$inc --include=$g"; done
  # shellcheck disable=SC2086  # word splitting of $inc and $SRC_DIRS is intended
  (cd "$PROJECT_DIR" && grep -rnIE $inc \
      --exclude-dir=deps --exclude-dir=_build --exclude-dir=test \
      --exclude-dir=node_modules --exclude-dir=security-audit --exclude-dir=static \
      -e "$re" $SRC_DIRS 2>/dev/null) | to_tsv "$id" \
    | { if [ -n "$excl" ]; then grep -vE -e "$excl"; else cat; fi; } >> "$GREP_FILE"
}

# grep_file ID REGEX FILE : grep a single file (relative to project).
grep_file() {
  [ -f "$PROJECT_DIR/$3" ] || return 0
  (cd "$PROJECT_DIR" && grep -nIE -e "$2" "$3" 2>/dev/null) \
    | sed "s|^|$3:|" | to_tsv "$1" >> "$GREP_FILE"
}

# emit ID FILE LINE MESSAGE : record a synthetic finding.
emit() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$GREP_FILE"
}

info "grep supplement"

# Identifier boundary helper for ERE (no \b in POSIX ERE).
NB='(^|[^A-Za-z0-9_.:])'

grep_src EXS-ATOM-001 '(String|List)\.to_atom[[:space:]]*\(|String\.to_atom[[:space:]]*$|\|>[[:space:]]*String\.to_atom|:erlang\.(binary|list)_to_atom[[:space:]]*\(' 'to_atom[[:space:]]*\("[^"#]*"\)'
grep_src EXS-ATOM-002 'keys:[[:space:]]*:atoms([^!A-Za-z0-9_]|$)' ''
grep_src EXS-DESER-001 ':erlang\.binary_to_term[[:space:]]*\(' ''
grep_src EXS-RCE-001 'Code\.(eval_string|eval_quoted|eval_file|compile_string|compile_quoted)([^A-Za-z0-9_]|$)|EEx\.eval_(string|file)([^A-Za-z0-9_]|$)' ''
grep_src EXS-CMD-001 ':os\.cmd[[:space:]]*\(|System\.shell[[:space:]]*\(|System\.cmd[[:space:]]*\([[:space:]]*"(/usr)?(/bin/)?(sh|bash|zsh|dash)"' ''
grep_src EXS-SQLI-001 'fragment[[:space:]]*\([[:space:]]*"[^"]*#\{' ''
grep_src EXS-SQLI-002 '(Repo\.query!?|SQL\.query!?|Ecto\.Adapters\.SQL\.query!?|Repo\.query_many!?)[[:space:]]*\(.*#\{' ''
grep_src EXS-XSS-001 "${NB}raw[[:space:]]*\\(|Phoenix\\.HTML\\.raw" '' '*.ex' '*.exs'
grep_src EXS-XSS-001 "${NB}raw[[:space:]]*[(@]|<%=[[:space:]]*raw[[:space:]]|Phoenix\\.HTML\\.raw" '' '*.heex' '*.eex' '*.leex' '*.sface'
grep_src EXS-REDOS-001 'Regex\.compile!?[[:space:]]*\([[:space:]]*[^"[:space:]~]|~r[/|({\[].*#\{' 'Regex\.compile!?[[:space:]]*\([[:space:]]*@[a-z_0-9]+[[:space:]]*\)'
grep_src EXS-PATH-001 '(File\.(read|write|rm|rm_rf|cp|cp_r|stream|open|ls|mkdir_p|rename|ln_s)!?|Path\.(join|expand))[[:space:]]*\(.*(params|conn\.|socket\.|args|assigns)' ''
grep_src EXS-PATH-001 'send_file[[:space:]]*\([^,]+,[^,]+,[[:space:]]*[^"[:space:]]|send_download[[:space:]]*\([^,]+,[[:space:]]*\{:file,[[:space:]]*[^"[:space:]]' ''

# --- config checks -----------------------------------------------------------

for cdir in $CONFIG_DIRS; do
  for f in "$cdir/prod.exs" "$cdir/config.exs"; do
    grep_file EXS-CFG-001 '(secret_key_base|signing_salt)[[:space:]]*(:|=>)[[:space:]]*"[^"]{8,}"' "$f"
  done
done

# EXS-CFG-002: browser pipeline in router(s) missing CSRF / secure headers plugs.
ROUTERS=""
if [ -n "$LIB_DIRS" ]; then
  # shellcheck disable=SC2086
  ROUTERS=$(cd "$PROJECT_DIR" && find $LIB_DIRS -type f -name '*router.ex' 2>/dev/null)
fi
for r in $ROUTERS; do
  start=$(grep -nE '^[[:space:]]*pipeline[[:space:]]+:browser[[:space:]]+do' "$PROJECT_DIR/$r" | head -1 | cut -d: -f1)
  [ -n "$start" ] || continue
  block=$(awk -v s="$start" 'NR > s { if ($0 ~ /^[[:space:]]*end[[:space:]]*$/) exit; print }' "$PROJECT_DIR/$r")
  for plug in protect_from_forgery put_secure_browser_headers; do
    if ! printf '%s\n' "$block" | grep -Eq "^[[:space:]]*plug[[:space:]]+:?$plug"; then
      emit EXS-CFG-002 "$r" "$start" "pipeline :browser missing plug :$plug"
    fi
  done
done

# EXS-CFG-003: prod without force_ssl (also accept Plug.SSL in an endpoint).
for cdir in $CONFIG_DIRS; do
  prod="$cdir/prod.exs"
  [ -f "$PROJECT_DIR/$prod" ] || continue
  found=0
  for f in "$PROJECT_DIR/$prod" "$PROJECT_DIR/$cdir/runtime.exs"; do
    [ -f "$f" ] && grep -Eq '^[^#]*force_ssl' "$f" && found=1
  done
  if [ $found -eq 0 ] && [ -n "$LIB_DIRS" ]; then
    # shellcheck disable=SC2086
    if (cd "$PROJECT_DIR" && grep -rqE --include='*endpoint.ex' '^[^#]*plug[[:space:]]+Plug\.SSL' $LIB_DIRS 2>/dev/null); then
      found=1
    fi
  fi
  if [ $found -eq 0 ]; then
    emit EXS-CFG-003 "$prod" 1 "force_ssl not configured for prod (prod.exs/runtime.exs)"
  fi
done

GREP_COUNT=$(wc -l < "$GREP_FILE" | tr -d ' ')
tool_status grep ran "$GREP_COUNT hits"

# ---------------------------------------------------------------------------
# 8. Summarize
# ---------------------------------------------------------------------------

if have python3; then
  if ! python3 -I "$SCRIPT_DIR/summarize.py" "$OUT_DIR" "$PROJECT_DIR"; then
    warn "summarize.py failed - raw tool outputs are still in $OUT_DIR"
  fi
else
  warn "python3 not found - skipping summarize; raw outputs are in $OUT_DIR"
fi

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

echo ""
echo "== elixir-security-audit scan =="
echo "project: $PROJECT_DIR"
echo "output:  $OUT_DIR"
echo "tools:"
awk -F'\t' '{ printf "  %-10s %-8s %s\n", $1, $2, $3 }' "$TOOLS_FILE"
if [ -f "$OUT_DIR/findings.json" ]; then
  # findings.json is indent=2; count severities without needing jq.
  for sev in critical high medium low unknown; do
    n=$(grep -c "\"severity\": \"$sev\"" "$OUT_DIR/findings.json")
    printf '  %-9s %s\n' "$sev:" "$n"
  done
  echo "summary: $OUT_DIR/summary.md"
fi

exit 0
