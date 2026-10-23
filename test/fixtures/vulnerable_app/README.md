# vuln_app — DO NOT DEPLOY

> **Intentionally vulnerable.** This Phoenix 1.7 app exists only as a test target and
> demo for the `elixir-security-audit` Claude Code skill. Every `# VULN: EXS-*` comment
> marks a real, reachable vulnerability. Never run it on a public interface, never copy
> its code into a real project.

## What's inside

- One labelled instance of each pattern ID from `docs/PLAN.md` (`# VULN: EXS-XXX-NNN`
  on the line above the sink), each reachable from an HTTP route.
- `# SAFE:` look-alikes that a naive grep will hit but that are **not** vulnerabilities
  (triage practice).
- `sweet_xml 0.6.6` pinned on purpose (GHSA-qpmc-wprv-x746 / CVE-2019-15160).
- No database needed: the Repo is configured but not started in `:test`.

See [`EXPECTED.md`](EXPECTED.md) for the full map of findings, Sobelow coverage and
`mix deps.audit` output.

## Run

```sh
cd test/fixtures/vulnerable_app
mix deps.get
mix compile --warnings-as-errors
mix test
```

## Demo with Claude Code

```sh
cd test/fixtures/vulnerable_app
claude
> 이 앱 보안 점검하고 고쳐줘
```

or run the scanner directly:

```sh
../../../skills/elixir-security-audit/scripts/scan.sh .
cat security-audit/summary.md
```

Fixes produced during a demo should go on a throwaway branch; reset the fixture afterwards
(`git checkout -- test/fixtures/vulnerable_app`) so the integration test keeps its targets.
