# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org/lang/ko/)을 따릅니다.

## [0.1.0] - 2026-10-23

### 추가
- `elixir-security-audit` 스킬: 전제 확인 → 스캔 → 분류 → 수정 → 검증 → 보고 워크플로와 가드레일
- `scan.sh` / `summarize.py`: Sobelow, mix_audit, mix hex.audit, OSV-Scanner, Opengrep, BEAM grep 결과를 `findings.json`·`summary.md`로 통합 (umbrella 지원)
- EXS 패턴 카탈로그 15종 (`references/patterns.md`), 도달성 판정 가이드, Phoenix 설정 점검표
- Opengrep 룰 17개 (AST·taint·정규식, 일부 autofix)
- 일부러 취약한 Phoenix 테스트 앱과 통합 테스트, CI
- 사용자 프로젝트용 GitHub Actions 템플릿
- Codex Security · `/security-review` · Claude Security 비교 인포그래픽

[0.1.0]: https://github.com/baryonlabs/elixir-security-audit/releases/tag/v0.1.0
