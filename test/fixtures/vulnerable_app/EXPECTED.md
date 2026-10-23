# EXPECTED findings — vuln_app

Toolchain used to produce this file: Elixir 1.18.4 / OTP 27, phoenix 1.7.24,
phoenix_live_view 1.2.13, ecto 3.14.2, sobelow 0.16.0, mix_audit 2.1.5.

Line numbers point at the sink (the line right below the `# VULN:` label).
`test/fixtures/expected_findings.txt` is the machine-readable minimum set.

## True positives (one per ID)

| ID | Sink | Reachable from | Sobelow |
|----|------|----------------|---------|
| EXS-ATOM-001 | `lib/vuln_app/catalog.ex:22` `String.to_atom(field)` | `GET /products?sort=` | DOS.StringToAtom (low) |
| EXS-ATOM-002 | `lib/vuln_app/importer.ex:6` `Jason.decode(payload, keys: :atoms)` | `POST /api/import` `payload` | — |
| EXS-DESER-001 | `lib/vuln_app/preferences.ex:10` `:erlang.binary_to_term(raw)` | `prefs` cookie on `GET /preferences` | Misc.BinToTerm (high) |
| EXS-RCE-001 | `lib/vuln_app/calculator.ex:6` `Code.eval_string(formula)` | `GET /calc?formula=` | RCE.CodeModule (low) |
| EXS-CMD-001 | `lib/vuln_app/thumbnails.ex:6` `System.cmd("sh", ["-c", "convert " <> filename ...])` | `POST /api/thumbnails` `filename` | — (CI.System not triggered) |
| EXS-SQLI-001 | `priv/examples/sqli_fragment.exs:14` `fragment("... '#{name}'")` | not compiled, see below | — |
| EXS-SQLI-002 | `lib/vuln_app/reports.ex:8` `Ecto.Adapters.SQL.query(Repo, "... '#{status}'", [])` | `GET /api/reports/orders?status=` | SQL.Query (low) |
| EXS-XSS-001 | `lib/vuln_app_web/components/comment_html.ex:13` `{raw(@comment)}` | `GET /comments/preview?comment=` | XSS.Raw (low) |
| EXS-REDOS-001 | `lib/vuln_app/search.ex:8` `Regex.compile!(pattern)` | `GET /search?pattern=` | — |
| EXS-PATH-001 | `lib/vuln_app/files.ex:8` `File.read!(Path.join(@upload_dir, name))` | `GET /download?file=` | Traversal.FileModule (low) |
| EXS-CFG-001 | `config/prod.exs:8` `secret_key_base: "pY3k..."` | config | Config.Secrets (high) |
| EXS-CFG-002 | `lib/vuln_app_web/router.ex:5` `pipeline :browser` without `:put_secure_browser_headers` | every browser route | Config.Headers (high) |
| EXS-CFG-003 | `config/prod.exs:4` endpoint config without `force_ssl` | config | Config.HTTPS (high) |
| EXS-DEP-001 | `mix.exs:37` / `mix.lock` `sweet_xml 0.6.6` | `POST /api/feeds` `xml` (uses SweetXml.xpath) | n/a (mix_audit) |

Reachability is exercised by `test/vuln_app_web/routes_test.exs` for every sink except
CMD-001 (would execute a shell) and SQLI-002 (needs Postgres).

### Sobelow coverage summary

`mix sobelow --format json --private` catches **9 of the 13** code/config IDs:
ATOM-001, DESER-001, RCE-001, SQLI-002, XSS-001, PATH-001, CFG-001, CFG-002, CFG-003
(DEP-001 is mix_audit's job, not Sobelow's).

Not caught by Sobelow (must come from grep/semgrep): **ATOM-002, CMD-001, REDOS-001, SQLI-001**.

Sobelow also reports two items that are not in the ID set:

- `Traversal.FileModule` on `lib/vuln_app/files.ex:14` (`File.read` in `read_upload_safe/1`)
  — **false positive**, the path was validated with `Path.safe_relative/2`.
- `XSS.SendResp` (medium) on `lib/vuln_app_web/controllers/comment_controller.ex:12`
  — same root cause as EXS-XSS-001 (the HTML body contains the `raw` output); triage
  should merge it into XSS-001 rather than count it twice.

Raw Sobelow findings (type | file line):

```
high_confidence   | Config.HTTPS: HTTPS Not Enabled                     | config/prod.exs 0
high_confidence   | Config.Secrets: Hardcoded Secret                    | config/prod.exs 8
high_confidence   | Misc.BinToTerm: Unsafe `binary_to_term`             | lib/vuln_app/preferences.ex 10
high_confidence   | Config.Headers: Missing Secure Browser Headers      | lib/vuln_app_web/router.ex 5
low_confidence    | RCE.CodeModule: Code Execution in `Code.eval_string` | lib/vuln_app/calculator.ex 6
low_confidence    | DOS.StringToAtom: Unsafe `String.to_atom`           | lib/vuln_app/catalog.ex 22
low_confidence    | Traversal.FileModule: Directory Traversal in `File.read!` | lib/vuln_app/files.ex 8
low_confidence    | Traversal.FileModule: Directory Traversal in `File.read`  | lib/vuln_app/files.ex 14
low_confidence    | SQL.Query: SQL injection                            | lib/vuln_app/reports.ex 8
low_confidence    | XSS.Raw: XSS                                        | lib/vuln_app_web/components/comment_html.ex 13
medium_confidence | XSS.SendResp: XSS in `send_resp`                    | lib/vuln_app_web/controllers/comment_controller.ex 12
```

## EXS-DEP-001 — `mix deps.audit` output

Pinned `{:sweet_xml, "0.6.6"}` (real advisory GHSA-qpmc-wprv-x746 / CVE-2019-15160,
"Inline DTD allows XML bomb attack", vulnerable `< 0.7.0`). `mix deps.audit` exits 1:

```
Name: sweet_xml
Version: 0.6.6
Lockfile: .../test/fixtures/vulnerable_app/mix.lock
URL: https://github.com/advisories/GHSA-qpmc-wprv-x746
Title: Inline DTD allows XML bomb attack
Severity: high
Vulnerable versions: < 0.7.0
First patched versions: 0.7.0

Vulnerabilities found!
```

Note: recent Hex also reports the advisory from `mix hex.audit` (exit 1) and prints a
warning during `mix deps.get`:

```
Advisories:
  sweet_xml 0.6.6 - GHSA-qpmc-wprv-x746 (HIGH)
    aka: CVE-2019-15160
    Inline DTD allows XML bomb attack
    https://osv.dev/vulnerability/GHSA-qpmc-wprv-x746
```

So `hex.audit` output is not only "retired packages" (EXS-DEP-002) — a scanner parsing it
should map the `Advisories:` section to EXS-DEP-001. There are no retired packages here, so
**EXS-DEP-002 is not expected**.

Fix: `{:sweet_xml, "~> 0.7"}` then `mix deps.update sweet_xml` (0.7.x is API-compatible
for the `xpath/2` + `~x` usage in `lib/vuln_app/feeds.ex`).

## EXS-SQLI-001 — why it lives in `priv/examples/`

Ecto refuses interpolated strings in `fragment/1` at compile time:

```
** (Ecto.Query.CompileError) to prevent SQL injection attacks, fragment(...) does not allow
strings to be interpolated as the first argument via the `^` operator,
got: `"lower(name) = '#{name}'"`
```

There is no compiling form of SQLI-001 reachable from user input, so the instance is in
`priv/examples/sqli_fragment.exs`, which is outside `elixirc_paths` and never compiled.
Static scanners (grep/semgrep) must include `*.exs` under `priv/` to pick it up.

## SAFE look-alikes (must be triaged as false positives)

| File | Code | Looks like | Why safe |
|------|------|-----------|----------|
| `lib/vuln_app/catalog.ex:11` | `@default_sort String.to_atom("name")` | ATOM-001 | compile-time literal |
| `lib/vuln_app/importer.ex:11` | `Jason.decode(payload, keys: :atoms!)` | ATOM-002 | `:atoms!` only uses existing atoms |
| `lib/vuln_app/thumbnails.ex:11` | `System.cmd("convert", [filename, ...])` | CMD-001 | no shell, argv element |
| `lib/vuln_app/reports.ex:13` | `SQL.query(Repo, "... $1", [status])` | SQLI-002 | parameterized |
| `lib/vuln_app/reports.ex` | `fragment("? >= ?", o.total, ^min_total)` | SQLI-001 | literal fragment + pinned params |
| `lib/vuln_app/search.ex:14` | `Regex.compile!(@slug_pattern)` | REDOS-001 | developer constant |
| `lib/vuln_app/files.ex:13-14` | `Path.safe_relative/2` then `File.read` | PATH-001 | traversal rejected |
| `lib/vuln_app_web/components/comment_html.ex:20` | `Phoenix.HTML.raw(@banner_html)` | XSS-001 | static trusted string |
| `lib/vuln_app_web/endpoint.ex` | `signing_salt: "Xq3vL9pz"` | CFG-001 | salt is not a secret (Phoenix default pattern); in `lib/`, not `config/` |
| `config/dev.exs`, `config/test.exs` | `secret_key_base: String.duplicate(...)` | CFG-001 | non-prod, not a literal |
