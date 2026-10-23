# 기여 가이드

## 개발 환경

- Elixir 1.14+ (CI는 1.18.4 / OTP 27), Python 3, bash
- 룰 테스트: [Opengrep](https://github.com/opengrep/opengrep) (Semgrep OSS는 Elixir 룰을 실행하지 않습니다)

```bash
bash test/run.sh          # 취약 앱 스캔 → 기대 EXS ID 전부 탐지 확인
bash test/rules/run.sh    # Opengrep 룰 테스트 (OPENGREP=/path/to/opengrep)
```

## 새 탐지 패턴 추가 체크리스트

1. `skills/elixir-security-audit/references/patterns.md`에 ID(`EXS-<유형>-NNN`), 위험, 취약/안전 코드, 오탐 신호, 테스트 아이디어를 추가
2. `docs/PLAN.md` 카탈로그 표에 한 줄 추가 (기본 심각도 포함)
3. `scripts/scan.sh` grep 보완 검사 또는 `rules/elixir-security.yml` Opengrep 룰 추가 (`metadata.exs_id` 필수)
4. `test/rules/`에 `# ruleid:` / `# ok:` 주석 테스트 추가
5. `test/fixtures/vulnerable_app`에 `# VULN: <ID>` 한 건과, 가능하면 `# SAFE:` 유사 코드 한 건 추가
6. `test/fixtures/expected_findings.txt`에 ID 추가
7. 두 테스트가 통과하는지 확인

## 원칙

- CVE·GHSA 번호는 OSV(`https://api.osv.dev/v1/vulns/<ID>`)에서 확인된 것만 씁니다.
- 레퍼런스 링크는 hexdocs, erlang.org, ERLEF, OWASP, 공식 권고만 씁니다.
- 스크립트는 macOS bash 3.2와 GNU 둘 다에서 동작해야 하고, Python은 표준 라이브러리만 씁니다.

## 커밋·PR

- 커밋 메시지: `feat:`, `fix:`, `docs:`, `test:`, `ci:` 접두사
- PR에는 무엇을 탐지하게 되는지, 오탐 가능성, 테스트 결과를 적어 주세요.
