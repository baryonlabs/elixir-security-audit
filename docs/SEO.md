# SEO / AEO / GEO / LLMO / NEO 작업 기록 — elixir-security-audit 사이트

- 사이트: https://baryonlabs.github.io/elixir-security-audit/ (GitHub Pages 프로젝트 페이지)
- 작업일: 2026-10-23 · 방법: fire-your-seo-agency (정공법만, 가시 텍스트 = JSON-LD, curl로 검증)
- 정본 데이터: 저장소의 README.md, CHANGELOG.md, `skills/elixir-security-audit/references/*.md`, `test/fixtures/vulnerable_app/EXPECTED.md`. 사이트의 숫자는 모두 여기서 왔다.

## Phase 0 점수표

| 레인 | Before (사이트 없음, GitHub README만) | After (로컬 curl 검증) |
|---|---|---|
| SEO | ❌ 전용 도메인 페이지 없음, 사이트맵·canonical 없음 | ✅ 정적 HTML 5쪽, 페이지마다 title 50–60자·description 150–160자·canonical·OG·twitter 카드, sitemap.xml, 404.html |
| AEO | ❌ 질문별 랜딩 0, FAQ 구조화 데이터 0 | ✅ 질문 랜딩 3종(h1 = 질문, 첫 문단 직답), 보이는 FAQ + FAQPage LD 5쪽 |
| GEO | ❌ llms.txt 없음, AI 크롤러 정책 없음 | ✅ llms.txt·llms-full.txt, robots.txt에 학습·검색·fetch 봇 명시 허용 (⚠️ 아래 "남은 일" 1번 참고) |
| LLMO | ⚠️ README는 강한 학습 표면이나 엔티티 연결 없음 | ✅ Organization(`#org`)·SoftwareSourceCode(`#code`)·SoftwareApplication(`#app`) @id 고정, 이름 표기 `elixir-security-audit` 통일 |
| NEO | ❌ 한국어 랜딩 없음 | ✅ 한국어 기본(lang="ko") + 영어 미러, 모바일 360px 대응, 라벨-값 표 위주 구성. 서치어드바이저 등록은 사용자 계정 필요 |
| 콘텐츠 | ❌ 질문 매핑 0 | ⚠️ 질문 3개 매핑. 발행 리듬·백로그는 아직 없음 |

## 구현한 것 (레인별)

### SEO
- 페이지: `/`(ko), `/en/`, `/ko/atom-exhaustion/`, `/ko/binary-to-term/`, `/ko/sobelow-vs-semgrep/` — 폴더/index.html로 깔끔한 URL, JS 없음
- 모든 내부 링크·자산은 상대 경로(프로젝트 하위 경로 `/elixir-security-audit/`에서 동작), canonical·og:url·sitemap은 절대 URL
- hreflang ko/en/x-default를 `/`와 `/en/` 양쪽에 상호 참조 + sitemap의 `xhtml:link`
- JSON-LD: Organization(전 페이지 동일 @id), SoftwareSourceCode(codeRepository, programmingLanguage Elixir/Shell/Python, MIT, author Baryon Labs), SoftwareApplication(DeveloperApplication, price 0), TechArticle(질문 페이지), FAQPage(보이는 FAQ가 있는 5쪽), BreadcrumbList(하위 페이지)
- OG 이미지 `og.png` 1200×630 (docs/elixir-steps.webp에서 제목이 보이게 크롭, 약 555KB)
- 이미지에 width/height, 첫 화면 아래 이미지는 `loading="lazy"`, CSS 1개(외부 요청 없음), SVG 파비콘
- `404.html` (GitHub Pages가 없는 경로에 404 상태로 제공)

### AEO
- 질문 하나 = 페이지 하나: "String.to_atom이 왜 위험한가요?", ":erlang.binary_to_term을 안전하게 쓰려면?", "Sobelow만으로 충분한가요?"
- 각 페이지 첫 문단에 직답, 아래에 표·코드·기준(도구 버전, 2026-10-23 기준) 제시
- 홈 첫 문단: "elixir-security-audit은 … 오픈소스 Claude Code 스킬입니다" 직답

### GEO
- `llms.txt`(안내서) + `llms-full.txt`(EXS 카탈로그, 워크플로, 설치, 테스트 앱 실측치)
- `robots.txt`: GPTBot, ClaudeBot, Google-Extended, CCBot, Applebot-Extended, OAI-SearchBot, Claude-SearchBot, PerplexityBot, ChatGPT-User, Claude-User, Perplexity-User, Googlebot, Bingbot, Yeti 모두 Allow + Sitemap 줄
- 1차 소스 수치: Sobelow 13종 중 9종 탐지(테스트 앱, sobelow 0.16.0), atom 한도 1,048,576, EXS 15종, Opengrep 룰 17개

### LLMO
- 엔티티 이름 표기 통일(`elixir-security-audit`, `Baryon Labs`), Organization `sameAs` = GitHub 조직
- README 상단 내비에 Website 링크 추가 → 저장소(학습 표면)와 사이트 연결

### NEO
- 한국어 본문이 기본 언어, 모바일 우선 레이아웃(360px에서 가로 스크롤 없음, 표·코드만 개별 스크롤)
- AI 브리핑이 잘라 가기 좋은 라벨-값 표(패턴 ID·심각도·위험 함수·Sobelow 검사)

### 콘텐츠
- 질문 랜딩 3종은 patterns.md·EXPECTED.md의 사실만 사용, 취약/안전 코드 쌍 포함

## 남은 일 (사용자 계정·권한 필요)

1. **robots.txt·llms.txt 위치 한계**: 크롤러는 호스트 루트(`https://baryonlabs.github.io/robots.txt`, `/llms.txt`)만 읽는다. 프로젝트 페이지의 `/elixir-security-audit/robots.txt`는 참고용일 뿐 효력이 없다. 실효를 원하면 `baryonlabs/baryonlabs.github.io` 사용자 사이트 저장소에 robots.txt(각 프로젝트 사이트맵 줄 포함)와 llms.txt를 두거나, 사용자 정의 도메인을 붙인다. GitHub Pages 기본값은 크롤링을 막지 않으므로 색인 자체는 문제없다.
2. **Pages 활성화**: 저장소 Settings → Pages → Source를 "GitHub Actions"로 두고 `.github/workflows/pages.yml` 실행 (lead 담당).
3. **Google Search Console**: URL 접두어 속성 `https://baryonlabs.github.io/elixir-security-audit/` 등록(HTML 파일 또는 meta 태그 확인) → sitemap.xml 제출 → 질문 페이지 3개 URL 검사·색인 요청.
4. **Bing Webmaster Tools**: GSC에서 가져오기 → 사이트맵 확인. ChatGPT 검색·Copilot이 Bing 색인을 쓰므로 필수. IndexNow는 키 파일을 루트에 둘 수 있을 때 연동.
5. **네이버 서치어드바이저**: 사이트 등록·소유 확인(meta 태그 방식이면 index.html에 태그 추가 후 재배포) → 사이트맵 제출 → 수집 요청.
6. 배포 후 Rich Results Test / schema.org validator로 JSON-LD 재확인.

## 측정 계획

배포일을 D0로 기록하고 **D0 + 14일에 재측정**한다(집계 지연을 감안해 최근 2–3일 제외).

| 지표 | 기준선(D0) | 방법 |
|---|---|---|
| 색인 | 0 | `site:baryonlabs.github.io/elixir-security-audit` (Google·Bing), GSC 색인 페이지 수 |
| 노출·클릭 | 0 | GSC·서치어드바이저 28일 노출/클릭, 검색어 Top |
| AI 인용 | 0/6 | 아래 질문을 Perplexity·ChatGPT(검색)·네이버 AI 브리핑에 던져 출처 인용 O/X |
| 크롤러 방문 | 측정 불가 | GitHub Pages는 접근 로그가 없음 → 인용 결과로 대체 |

AI 인용 점검 질문:
1. Elixir Phoenix 보안 점검 도구 추천
2. String.to_atom 왜 위험해
3. erlang binary_to_term 안전하게 쓰는 법
4. Sobelow만으로 충분해?
5. Semgrep Elixir 룰 0건 나옴
6. Claude Code Elixir security audit plugin

보고 형식: `[기준선] D0 … [변경] 사이트 공개 … [재측정 D0+14] 노출 · 클릭 · AI 인용 n/6`. 노출 상위 검색어 중 전용 페이지가 없는 질문이 다음 랜딩 후보다(예: EXS-SQLI-001 fragment 컴파일 에러, Opengrep 설치).

## 하지 않은 것
- 백링크 요청·교환, 숨긴 텍스트, 가시 텍스트와 다른 구조화 데이터 — 원칙상 하지 않음
- 영어 질문 랜딩(현재 한국어만), aggregateRating(실제 평점 데이터 없음)
