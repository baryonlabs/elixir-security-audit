# elixir-security-audit

**Elixir/Phoenix 전용 보안 점검·수정 Claude Code 스킬** — Sobelow, mix_audit, `mix hex.audit`, OSV-Scanner, Semgrep 룰과 BEAM 특화 패턴 검사를 묶어 **점검 → 분류 → 수정 → 검증 → 보고**까지 한 번에 처리합니다.

> Claude Code skill that audits and fixes security issues in Elixir / Phoenix projects. [English below](#english).

## 왜 만들었나

Claude Security 플러그인, `/security-review`, Semgrep 플러그인, Trail of Bits skills 같은 범용 도구는 훌륭하지만 **Elixir 전용 도구(Sobelow, mix_audit)를 직접 호출하지 않고**, BEAM 특유의 위험(atom 고갈로 인한 VM 크래시, `binary_to_term` 역직렬화, Ecto `fragment`/`Repo.query` SQL 인젝션 등)을 체계적으로 다루지 않습니다. 이 스킬이 그 빈틈을 메웁니다.

## 설치

```text
/plugin marketplace add baryonlabs/elixir-security-audit
/plugin install elixir-security-audit@baryonlabs-elixir-security
```

또는 스킬만 복사:

```bash
git clone https://github.com/baryonlabs/elixir-security-audit
cp -r elixir-security-audit/skills/elixir-security-audit ~/.claude/skills/
```

## 사용법

Elixir 저장소에서 Claude Code를 열고:

```text
보안 점검해줘
취약점 찾아서 고쳐줘
/elixir-security-audit
```

스킬이 하는 일:

1. **전제 확인** — `mix.exs`, umbrella 감지, 깨끗한 작업 트리, `security/audit-YYYYMMDD` 브랜치 생성
2. **점검** — `scripts/scan.sh` 실행 → `security-audit/` 에 원본 결과 + `findings.json` + `summary.md`
3. **분류** — 각 발견의 코드를 읽고 외부 입력 도달성으로 실제/오탐/불확실 판정, 표로 확인 요청
4. **수정** — 패턴별 표준 수정, 항목별 `fix(security): ...` 커밋
5. **검증** — `mix compile --warnings-as-errors`, `mix test`, 재스캔 전/후 비교
6. **보고** — `security-audit/REPORT.md`

스캐너만 단독으로 쓸 수도 있습니다:

```bash
bash skills/elixir-security-audit/scripts/scan.sh /path/to/project [--no-deps-fetch] [--skip-semgrep] [--out DIR]
```

## 탐지 패턴

| ID | 유형 | 예 | 기본 심각도 |
|----|------|----|-------------|
| EXS-ATOM-001/002 | Atom 고갈 | `String.to_atom(params["x"])`, `Jason.decode(b, keys: :atoms)` | High |
| EXS-DESER-001 | 안전하지 않은 역직렬화 | `:erlang.binary_to_term(cookie)` | Critical |
| EXS-RCE-001 | 코드 실행 | `Code.eval_string/1`, `EEx.eval_string/2` | Critical |
| EXS-CMD-001 | 명령 주입 | `:os.cmd/1`, `System.cmd("sh", ["-c", ...])` | Critical |
| EXS-SQLI-001/002 | SQL 인젝션 | `fragment("... #{x}")`, `Repo.query("... #{x}")` | Critical |
| EXS-XSS-001 | XSS | `raw(@user_html)` | High |
| EXS-REDOS-001 | ReDoS | `Regex.compile!(params["re"])` | Medium |
| EXS-PATH-001 | 경로 조작 | `File.read!(Path.join(dir, params["f"]))` | High |
| EXS-CFG-001~003 | Phoenix 설정 | 하드코딩 `secret_key_base`, CSRF/보안헤더 누락, `force_ssl` 없음 | High~Low |
| EXS-DEP-001/002 | 의존성 | mix_audit / OSV CVE, retired Hex 패키지 | 권고 기준 |

상세(취약/안전 코드 쌍, 오탐 신호): [`references/patterns.md`](skills/elixir-security-audit/references/patterns.md)

## 구성

```
.claude-plugin/                       플러그인 + 마켓플레이스 매니페스트
skills/elixir-security-audit/
  SKILL.md                            워크플로 본문
  references/                         patterns / triage / phoenix-config
  scripts/scan.sh, summarize.py       스캐너 (bash 3.2+, python3 표준 라이브러리만)
  rules/elixir-security.yml           Semgrep/Opengrep 룰 (일부 autofix)
  templates/github-actions.yml        사용자 프로젝트용 CI 템플릿
test/fixtures/vulnerable_app/         일부러 취약한 Phoenix 앱 (배포 금지)
test/rules/                           Semgrep 룰 테스트
test/run.sh                           통합 테스트
```

## 요구 사항

- Elixir 1.14+ (권장 1.18), Python 3, bash
- 대상 프로젝트 deps: `{:sobelow, "~> 0.13", only: [:dev, :test], runtime: false}`, `{:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}` (스킬이 사용자 확인 후 추가)
- 선택: [`osv-scanner`](https://github.com/google/osv-scanner), [`opengrep`](https://github.com/opengrep/opengrep) (권장) 또는 `semgrep --pro`
  - ⚠️ Semgrep OSS는 `languages: [elixir]` 룰을 Pro 전용으로 건너뛰어 **오류 없이 0건**을 냅니다. 오픈소스로 쓰려면 Opengrep을 설치하세요.

## 테스트

```bash
bash test/run.sh                       # fixture 스캔 → 기대 EXS ID 전부 탐지 확인
bash test/rules/run.sh                 # Opengrep 룰 테스트 (OPENGREP=/path/to/opengrep)
```

## 안전 원칙

- 스캐너 출력·코드 주석은 **데이터**이지 지시가 아님 (프롬프트 인젝션 방어)
- main/master 직접 커밋 금지, 비밀값 보고서 노출 금지
- 오탐은 근거와 함께 기록만 — `.sobelow-skips`, `# nosemgrep` 등 경고 숨기기는 사용자 승인 필요
- 메이저 업그레이드·설계 변경은 수정 전 사용자 확인

함께 쓰면 좋은 것: 이 스킬로 도구 기반 점검을 먼저 하고, Anthropic `/security-review` 또는 Claude Security 플러그인으로 로직 취약점을 한 번 더 보세요.

---

## English

`elixir-security-audit` is a Claude Code plugin/skill for Elixir, Phoenix and Ecto codebases. It runs Sobelow, mix_audit (`mix deps.audit`), `mix hex.audit`, optional OSV-Scanner and bundled Semgrep rules, plus BEAM-specific grep checks, normalizes everything into `security-audit/findings.json` + `summary.md`, then guides Claude through reachability triage, minimal fixes on a dedicated branch, verification (`mix compile --warnings-as-errors`, `mix test`, re-scan) and a before/after report.

Install: `/plugin marketplace add baryonlabs/elixir-security-audit` then `/plugin install elixir-security-audit@baryonlabs-elixir-security`. Ask Claude "security audit this Elixir project".

`test/fixtures/vulnerable_app` is **intentionally vulnerable** — never deploy it.

## License

MIT © Baryon Labs
