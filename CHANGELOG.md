# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org/lang/ko/)을 따릅니다.

## [0.2.1] - 2026-11-14

### 문서
- README: OpenCode에서 스킬을 실행하는 방법 보강 — `@elixir-security-audit` 멘션, `opencode run` 헤드리스 실행, 스캐너 단독 실행, `/reload` 문제 해결

## [0.2.0] - 2026-11-14

### 추가
- OpenCode 호환: `.opencode/skills/elixir-security-audit` 심볼릭 링크, README에 OpenCode / 다른 에이전트 설치 안내
- `test/opencode.sh`: 복사한 스킬 디렉터리에서 `CLAUDE_PLUGIN_ROOT` 없이 통합 테스트 실행, CI 포함

### 변경
- SKILL.md: `CLAUDE_PLUGIN_ROOT` 없이도 동작하도록 스캔 명령을 스킬 디렉터리 기준으로 수정

## [0.1.0] - 2026-10-23

### 추가
- `elixir-security-audit` 스킬: 전제 확인 → 스캔 → 분류 → 수정 → 검증 → 보고 워크플로와 가드레일
- `scan.sh` / `summarize.py`: Sobelow, mix_audit, mix hex.audit, OSV-Scanner, Opengrep, BEAM grep 결과를 `findings.json`·`summary.md`로 통합 (umbrella 지원)
- EXS 패턴 카탈로그 15종 (`references/patterns.md`), 도달성 판정 가이드, Phoenix 설정 점검표
- Opengrep 룰 17개 (AST·taint·정규식, 일부 autofix)
- 일부러 취약한 Phoenix 테스트 앱과 통합 테스트, CI
- 사용자 프로젝트용 GitHub Actions 템플릿
- Codex Security · `/security-review` · Claude Security 비교 인포그래픽

[0.2.1]: https://github.com/baryonlabs/elixir-security-audit/releases/tag/v0.2.1
[0.2.0]: https://github.com/baryonlabs/elixir-security-audit/releases/tag/v0.2.0
[0.1.0]: https://github.com/baryonlabs/elixir-security-audit/releases/tag/v0.1.0
