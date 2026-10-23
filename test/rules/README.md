# Rule tests

Annotated tests for `skills/elixir-security-audit/rules/elixir-security.yml`.

```sh
test/rules/run.sh                       # all checks (needs opengrep on PATH or OPENGREP=...)

# or one target at a time
opengrep validate skills/elixir-security-audit/rules/elixir-security.yml
opengrep test --config skills/elixir-security-audit/rules/elixir-security.yml test/rules/elixir-security.ex
```

Verified with **Opengrep 1.32.0** (macOS arm64 binary from
https://github.com/opengrep/opengrep/releases). Rule files also pass
`semgrep --validate` on Semgrep 1.182.1.

| File | Covers |
|------|--------|
| `elixir-security.ex` | all `languages: [elixir]` rules, `# ruleid:` / `# ok:` annotations |
| `elixir-security.fixed.ex` | expected autofix output (ATOM-001, ATOM-002, DESER-001) |
| `config/prod.exs` | EXS-CFG-001 (`exs-cfg-001`, `exs-cfg-001-salt`) |
| `config/dev.exs` | must NOT match (dev/test config excluded); checked by scan, not `opengrep test` |
| `templates/profile.html.heex` | `exs-xss-001-template` (regex), `<!-- ruleid: -->` annotations |

## Rule ids

One rule per EXS id (`exs-atom-001` ...), plus companion variants that share
the same `metadata.exs_id` — key on `metadata.exs_id`, not `check_id`:

| Variant | Why |
|---------|-----|
| `exs-atom-001-list` | `List.to_atom/1` needs a different autofix |
| `exs-deser-001-opts` | `binary_to_term/2`; not autofixed (options change return value) |
| `exs-xss-001-template` | regex for `*.heex`/`*.eex` (templates are not parsed) |
| `exs-redos-001-sigil` | regex for `~r/...#{x}.../` |
| `exs-path-001-param` | any function argument as source (LOW confidence); covers the controller → context-module case that intraprocedural taint misses |
| `exs-cfg-001-salt` | `signing_salt`/`encryption_salt` literals in prod/runtime config |

## Caveats

- **Semgrep OSS does not run these rules.** Semgrep 1.182.1 accepts the file
  but skips every Elixir rule ("require Pro"), reporting 0 findings. Use
  Opengrep, or `semgrep --pro` with a Semgrep login.
- `semgrep --test` with a config *file* plus a directory is not supported by
  `opengrep test` ("config must be a local directory"); with a config
  directory it only pairs rule files with same-basename targets. `run.sh`
  therefore passes each target explicitly.
- `opengrep test` ignores `paths:` include/exclude. Path-scoped behaviour is
  verified by `run.sh` with a real scan; in the `.ex` test file the raw/1
  lines are annotated for both `exs-xss-001` and `exs-xss-001-template`.
- `opengrep test` treats `*.fixed.ex` as a normal target when given a
  directory, so do not point it at `test/rules/` as a whole.
- Opengrep (like Semgrep) ignores `test/` paths relative to the git root by
  default; scan from inside the target project (`cd PROJECT && opengrep scan ... .`).
- HEEx/EEx templates are not parsed as Elixir; template XSS is a regex rule.
  Interpolation inside `~r` sigils is also matched by regex
  (`exs-redos-001-sigil`), since sigil contents are not exposed to patterns.
