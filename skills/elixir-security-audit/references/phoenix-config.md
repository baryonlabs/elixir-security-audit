# Phoenix 설정 점검 (Phoenix 1.7+)

대상 파일: `lib/<app>_web/endpoint.ex`, `lib/<app>_web/router.ex`, `config/config.exs`, `config/prod.exs`,
`config/runtime.exs`, `assets/js/app.js`. 관련 ID: EXS-CFG-001 (비밀), EXS-CFG-002 (CSRF/헤더/CSP/check_origin),
EXS-CFG-003 (TLS). 예시의 `MyApp` / `MyAppWeb` / `:my_app` 은 프로젝트 이름으로 바꾼다.

**컴파일 타임 vs 런타임 설정:** endpoint 의 `force_ssl`, `debug_errors`, `code_reloader` 는 `Application.compile_env`
로 읽힌다. `config/prod.exs` (또는 `config.exs`)에 둬야 하고, `runtime.exs` 에 두면 적용되지 않는다.
비밀값과 호스트명 같은 배포 환경 값은 `runtime.exs` 에 둔다.

## 점검표

| # | 항목 | 확인 위치 | 기대 상태 | ID |
|---|------|-----------|-----------|----|
| 1 | CSRF 보호 | router `:browser` 파이프라인 | `plug :protect_from_forgery` | CFG-002 |
| 2 | 보안 헤더 | router `:browser` 파이프라인 | `plug :put_secure_browser_headers` | CFG-002 |
| 3 | CSP | `put_secure_browser_headers` 인자 | 앱에 맞는 `content-security-policy` | CFG-002 |
| 4 | HTTPS 강제 / HSTS | `config/prod.exs` | `force_ssl: [hsts: true]` | CFG-003 |
| 5 | 비밀값 | `config/*.exs` | prod 비밀은 `runtime.exs` + `System.fetch_env!/1` | CFG-001 |
| 6 | 세션 쿠키 | endpoint `@session_options` | `same_site`, https 에서 `secure`, 필요시 `encryption_salt` | CFG-002 |
| 7 | WebSocket origin | endpoint `socket`, endpoint config | `check_origin` 이 `false` 가 아님 | CFG-002 |
| 8 | CORS | CORS 플러그 설정 | 와일드카드 + 자격증명 조합 없음 | CFG-002 |
| 9 | 개발 기능 | `config/prod.exs` | `debug_errors`, `code_reloader` 가 prod 에서 꺼짐 | CFG-002 |
| 10 | 로그 필터 | `config/config.exs` | `:filter_parameters` 에 비밀번호·토큰 키 | CFG-002 |

## 1–3. 브라우저 파이프라인: CSRF, 보안 헤더, CSP

```elixir
# lib/my_app_web/router.ex
@csp "default-src 'self'; " <>
       "script-src 'self'; " <>
       "style-src 'self'; " <>
       "img-src 'self' data:; " <>
       "connect-src 'self'; " <>
       "frame-ancestors 'self'; " <>
       "base-uri 'self'; " <>
       "form-action 'self'"

pipeline :browser do
  plug :accepts, ["html"]
  plug :fetch_session
  plug :fetch_live_flash
  plug :put_root_layout, html: {MyAppWeb.Layouts, :root}
  plug :protect_from_forgery
  plug :put_secure_browser_headers, %{"content-security-policy" => @csp}
end
```

- `put_secure_browser_headers/2` 는 `x-content-type-options: nosniff`, `referrer-policy` 등 기본 헤더를 넣고,
  넘긴 맵으로 추가/덮어쓴다. 기본 헤더 집합은 버전마다 다르다: Phoenix 1.8 은 `x-frame-options` 대신 기본 CSP
  `base-uri 'self'; frame-ancestors 'self';` 를 넣고, 1.7 은 `x-frame-options` 를 넣지만 CSP 는 넣지 않는다.
  어느 쪽이든 앱 전용 CSP 가 없으면 Sobelow `Config.CSP` 가 잡는다.
- **CSP 는 프론트엔드를 깨뜨릴 수 있다 (사용자 확인 필요).** 인라인 `<script>`/`style` 속성, 외부 CDN, 분석 스크립트,
  `phx-*` 이외의 인라인 이벤트 핸들러를 먼저 조사한다. 처음에는 `"content-security-policy-report-only"` 헤더로 배포해
  위반을 수집한 뒤 강제 모드로 바꾸는 방식을 제안한다.
- LiveView WebSocket 은 같은 출처이면 `connect-src 'self'` 로 대부분 충분하다. 다른 호스트로 연결하면 `wss://<host>` 를 추가한다.
- `protect_from_forgery` 는 세션 쿠키를 쓰는 모든 파이프라인에 필요하다. `<.form>` / `Phoenix.HTML.Form` 은 토큰을 자동으로 넣는다.
  LiveView 는 root 레이아웃의 `<meta name="csrf-token" content={get_csrf_token()} />` 과 `app.js` 의
  `params: {_csrf_token: csrfToken}` 로 토큰을 보낸다 — 생성기 기본값이 지워지지 않았는지 확인한다.
- **CSRF via action reuse (Sobelow `Config.CSRFRoute`):** 같은 컨트롤러 액션을 `get` 과 `post` 둘 다에 연결하거나 `match :*` 를 쓰면
  GET 으로 상태 변경이 가능해져 CSRF 보호가 우회된다. 상태 변경은 POST/PUT/PATCH/DELETE 전용 액션으로 분리한다.
- API 파이프라인(`:api`)은 쿠키 세션을 쓰지 않으면 CSRF 플러그가 필요 없다. 쿠키 인증 API 라면 필요하다.

## 4. HTTPS 강제와 HSTS

```elixir
# config/prod.exs  (컴파일 타임 설정)
config :my_app, MyAppWeb.Endpoint,
  force_ssl: [hsts: true]

# TLS 를 로드밸런서/프록시에서 종료하는 경우
config :my_app, MyAppWeb.Endpoint,
  force_ssl: [hsts: true, rewrite_on: [:x_forwarded_proto]]
```

- `Plug.SSL` 의 `:hsts` 기본값은 `true`, `:expires` 기본 1년. `:subdomains`, `:preload` 는 영향 범위가 크므로 사용자 확인 후 켠다.
- `rewrite_on: [:x_forwarded_proto]` 는 프록시가 그 헤더를 **항상 덮어쓴다는** 전제에서만 안전하다 (클라이언트가 위조 가능).
- 헬스 체크가 HTTP 로 들어오면 리다이렉트로 실패할 수 있다. `:exclude` 옵션 또는 인프라 설정으로 처리한다.
- 인프라에서 이미 리다이렉트·HSTS 를 처리하면 EXS-CFG-003 은 근거를 받아 오탐으로 기록한다.

## 5. 비밀값은 runtime.exs 에서

```elixir
# config/runtime.exs
import Config

if config_env() == :prod do
  config :my_app, MyApp.Repo,
    url: System.fetch_env!("DATABASE_URL"),
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")

  host = System.fetch_env!("PHX_HOST")

  config :my_app, MyAppWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    secret_key_base: System.fetch_env!("SECRET_KEY_BASE")

  config :my_app, :stripe_api_key, System.fetch_env!("STRIPE_API_KEY")
end
```

- `config/prod.exs`, `config/config.exs` 에 `secret_key_base`, DB 비밀번호, API 키 리터럴이 있으면 EXS-CFG-001.
  `dev.exs` / `test.exs` 의 생성기 값은 오탐.
- 이미 커밋된 prod 비밀은 파일에서 지워도 git 히스토리에 남는다 → **교체(rotate)** 를 보고서의 "사용자 조치 필요" 에 적는다.
  값 원문은 보고서·커밋에 쓰지 않는다.
- 컴파일 타임에 비밀을 읽는 코드(`@key System.get_env("KEY")`, `Application.compile_env` 로 비밀 읽기)는 비밀이 빌드 산출물에
  박힌다 → 런타임 조회(`Application.fetch_env!/2`)로 바꾼다.

## 6. 세션 쿠키

```elixir
# lib/my_app_web/endpoint.ex
@session_options [
  store: :cookie,
  key: "_my_app_key",
  signing_salt: "GENERATED",
  encryption_salt: "GENERATED",
  same_site: "Lax",
  max_age: 60 * 60 * 24 * 14
]

socket "/live", Phoenix.LiveView.Socket,
  websocket: [connect_info: [session: @session_options]],
  longpoll: [connect_info: [session: @session_options]]

plug Plug.Session, @session_options
```

- 쿠키 세션은 기본적으로 **서명만** 되고 내용은 base64 로 읽힌다. 세션에 민감 정보가 있으면 `encryption_salt` 를 추가한다
  (추가 시 기존 세션이 무효화된다 — 사용자에게 알림). salt 값은 `mix phx.gen.secret 32` 로 만든다. salt 자체는 비밀이 아니다.
- `http_only` 는 Plug 기본값이 `true` 다. `http_only: false` 가 있으면 제거한다.
- `secure` 는 요청 scheme 이 https 이면 Plug 가 자동으로 붙인다. TLS 종료 프록시 뒤에서 `rewrite_on` 없이 동작하면 scheme 이
  http 로 보여 `secure` 가 빠진다 → 4절의 `rewrite_on` 을 쓰거나 prod 에서 `secure: true` 를 명시한다.
- `same_site: "Lax"` 가 기본 권장값. `"None"` 은 `secure` 필수이고 CSRF 위험이 커지므로 근거가 있을 때만.
- `max_age` 가 없으면 브라우저 세션 쿠키가 된다 (브라우저 종료 시 삭제, 서버 측 만료 없음). 로그인 세션 만료 정책은 인증 코드
  (예: `phx.gen.auth` 의 토큰 유효기간)에서도 확인한다.

## 7. LiveView / Channel `check_origin`

```elixir
# config/runtime.exs — 런타임 endpoint 설정으로 읽힌다
config :my_app, MyAppWeb.Endpoint,
  check_origin: ["https://example.com", "https://www.example.com"]
```

- 기본값 `true` 는 endpoint 의 `url: [host: ...]` 와 Origin 헤더를 비교한다. `url` 의 host 가 실제 도메인과 같으면 별도 설정이 필요 없다.
- `check_origin: false` (endpoint 설정 또는 `socket ... websocket: [check_origin: false]`)는 **Cross-Site WebSocket Hijacking**
  (Sobelow `Config.CSWH`)을 허용한다. 다른 사이트가 사용자의 쿠키로 LiveView/Channel 에 연결할 수 있다 → 허용 목록으로 바꾼다.
- 서브도메인 전체 허용은 `"//*.example.com"` 형식. 와일드카드는 신뢰하는 도메인에만 쓴다.
- dev 에서만 `false` 이고 prod 에서 기본값이면 오탐.

## 8. CORS

Phoenix 는 CORS 를 내장하지 않는다. `CORSPlug` 나 `Corsica` 같은 플러그를 쓰는 경우:

- 출처를 와일드카드(`"*"`)로 두면서 쿠키/자격증명을 허용하는 조합은 위험하다. 허용 출처를 명시 목록으로 둔다.
- 요청의 `Origin` 을 그대로 반사(reflect)하는 설정/코드는 와일드카드와 같다.
- 공개 읽기 전용 API 는 와일드카드가 정당할 수 있다 — 쿠키 인증을 쓰지 않는지 확인 후 오탐 처리.
- 플러그별 옵션 이름은 해당 라이브러리 문서를 확인한다 (버전마다 다르다).

## 9. 개발 기능은 prod 에서 끄기

```elixir
# config/dev.exs 에만 있어야 함
config :my_app, MyAppWeb.Endpoint,
  code_reloader: true,
  debug_errors: true,
  check_origin: false

# config/prod.exs 에 다음이 있으면 제거
#   debug_errors: true        → 스택트레이스·소스·환경 정보 노출
#   code_reloader: true
```

- `debug_errors: true` 는 `Plug.Debugger` 를 켜서 에러 페이지에 소스 코드와 요청 정보를 보여 준다.
- `Phoenix.LiveDashboard` / `Phoenix.LiveReloader` 라우트가 prod 에서 인증 없이 노출되지 않는지 router 의
  `if Application.compile_env(:my_app, :dev_routes)` 블록을 확인한다. prod 에서 대시보드를 쓰면 인증 파이프라인 뒤에 둔다.
- `config :phoenix, :plug_init_mode, :runtime`, `:stacktrace_depth` 같은 dev 설정이 prod 로 새지 않았는지 확인한다.

## 10. 로그에서 민감 파라미터 필터링

```elixir
# config/config.exs
config :phoenix, :filter_parameters, ["password", "secret", "token", "api_key"]
```

- Phoenix 기본값은 `["password"]` 다. 키 이름에 해당 문자열이 **포함되면** 필터링된다 (대소문자 구분).
  `access_token`, `refresh_token`, `client_secret`, `card_number` 같은 앱 고유 필드를 추가한다.
- 허용 목록 방식이 더 안전하다: `config :phoenix, :filter_parameters, {:keep, ["id", "page"]}`.
- 이 설정은 Phoenix 요청 로그에만 적용된다. 직접 `Logger.info(inspect(params))` 하는 코드, 외부 API 요청/응답 로그,
  `Ecto` 쿼리 로그의 파라미터는 별도로 확인한다. Ecto 스키마의 민감 필드에는 `redact: true` 를 붙여 `inspect` 출력에서 가린다.
