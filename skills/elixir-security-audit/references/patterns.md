# 패턴 카탈로그 (EXS-*)

각 패턴: **무엇** / **BEAM 에서 왜 위험한가** / 취약 코드 / 수정 코드 / 오탐 신호 / 테스트 아이디어.
ID 와 기본 심각도는 `docs/PLAN.md` 의 표와 같다. 심각도 조정은 [triage.md](triage.md) 참고.

공통 원칙: 값이 **외부 입력에서 오지 않으면** 대부분 오탐이다. 판정 전에 반드시 값의 출처를 역추적한다.

---

## EXS-ATOM-001 — 동적 atom 생성 (High)

**무엇:** `String.to_atom/1`, `List.to_atom/1`, `:erlang.binary_to_atom/2`, atom 보간 `:"user_#{id}"`,
`Module.concat/1,2` 에 외부 입력이 들어가는 경우. (Sobelow: `DOS.StringToAtom`, `DOS.ListToAtom`, `DOS.BinToAtom`)

**BEAM 특유의 위험:** atom 은 GC 되지 않는다. atom 테이블 한도(기본 1,048,576, `+t` 로 변경)에 도달하면
**VM 전체가 크래시**한다. 요청 하나당 atom 하나만 만들어도, 공격자가 서로 다른 문자열을 계속 보내면
노드 전체가 내려간다. 프로세스 격리나 supervisor 재시작으로 막을 수 없다.

취약:

```elixir
def index(conn, %{"sort" => sort}) do
  posts = Blog.list_posts(order_by: String.to_atom(sort))
  render(conn, :index, posts: posts)
end
```

수정 (허용 목록 — 권장):

```elixir
@sort_fields %{"title" => :title, "inserted_at" => :inserted_at}

def index(conn, params) do
  sort = Map.get(@sort_fields, params["sort"], :inserted_at)
  posts = Blog.list_posts(order_by: sort)
  render(conn, :index, posts: posts)
end
```

수정 (`String.to_existing_atom/1` — 차선):

```elixir
def parse_status(value) when is_binary(value) do
  atom = String.to_existing_atom(value)
  if atom in [:draft, :published, :archived], do: {:ok, atom}, else: :error
rescue
  ArgumentError -> :error
end
```

`to_existing_atom` 은 고갈은 막지만 **이미 존재하는 모든 atom**(모듈명, `:__struct__` 등)을 허용하므로
허용 목록 검사를 함께 해야 한다. Ecto 스키마라면 `Ecto.Enum` 필드로 캐스팅하는 것도 안전한 대안이다.

**오탐 신호:**
- 인자가 컴파일 타임 리터럴, 모듈 속성(`@kinds`), `~w(...)a` 목록에서만 온다.
- 컴파일 타임(매크로, `for` 로 함수 생성, `config/*.exs`)에서만 실행된다.
- 입력 집합이 구조적으로 유한하다 (예: 고정된 enum 컬럼 값을 `to_atom`) — 단, 사용자가 그 컬럼에 임의 값을 쓸 수 있으면 실제.
- mix task, 개발 스크립트, 테스트 코드.

**테스트 아이디어:**

```elixir
# async: false — 다른 테스트가 만드는 atom 과 섞이지 않게
test "unknown sort values do not create atoms", %{conn: conn} do
  before = :erlang.system_info(:atom_count)
  for i <- 1..500, do: get(conn, ~p"/posts?sort=unknown_#{i}_#{System.unique_integer()}")
  assert :erlang.system_info(:atom_count) - before < 50
end
```

---

## EXS-ATOM-002 — JSON 디코딩 시 atom 키 (High)

**무엇:** `Jason.decode(data, keys: :atoms)` / `Jason.decode!(data, keys: :atoms)` (Poison 의 `keys: :atoms` 도 동일).
`keys: :atoms!` 는 `String.to_existing_atom/1` 을 쓰므로 해당하지 않는다.

**BEAM 특유의 위험:** 요청 body 의 모든 키가 새 atom 이 된다. EXS-ATOM-001 과 같은 이유로 VM 크래시 DoS.
JSON 키는 공격자가 마음대로 만들 수 있으므로 한 요청으로 수천 개 atom 을 만들 수 있다.

취약:

```elixir
{:ok, payload} = Jason.decode(body, keys: :atoms)
handle_event(payload.type, payload)
```

수정:

```elixir
{:ok, payload} = Jason.decode(body)   # 문자열 키 (기본값)
handle_event(payload["type"], payload)

# atom 키가 꼭 필요하고 키 집합이 코드에 이미 존재할 때
case Jason.decode(body, keys: :atoms!) do
  {:ok, payload} -> handle_event(payload.type, payload)
  {:error, _} -> {:error, :invalid_payload}
end
```

`keys: :atoms!` 는 모르는 키가 오면 예외(`ArgumentError`)를 던질 수 있으니 rescue 하거나, 문자열 키 +
Ecto embedded schema / `Ecto.Changeset.cast/4` 로 검증하는 방식을 우선한다.

**오탐 신호:** 디코딩 대상이 컴파일 타임 파일(`priv/*.json` 을 `@external_resource` 로 읽음), 신뢰된 내부 설정,
테스트 픽스처.

**테스트 아이디어:** 임의 키 수백 개를 가진 JSON 을 보내고 `:erlang.system_info(:atom_count)` 증가가 없음을 확인.

---

## EXS-DESER-001 — 안전하지 않은 `binary_to_term` (Critical)

**무엇:** `:erlang.binary_to_term/1`, `:erlang.binary_to_term/2` 에 외부(또는 외부가 쓸 수 있는 저장소) 데이터. (Sobelow: `Misc.BinToTerm`)

**BEAM 특유의 위험:**
- 디코딩 과정에서 **atom 이 생성**된다 → 고갈 DoS.
- **fun(익명 함수)** 을 복원할 수 있다. `Enumerable` 은 함수에도 구현되어 있어서, 리스트를 기대한 자리에
  fun 이 들어오면 `Enum.map/2` 같은 호출만으로 공격자가 고른 함수가 **실행**된다 (RCE).
- `[:safe]` 옵션은 새 atom·새 외부 함수 참조 생성을 막지만, **이미 로드된 모듈의 fun 은 막지 못한다.**
  그래서 Plug 는 `Plug.Crypto.non_executable_binary_to_term/2` 를 제공한다 (fun 이 있으면 `ArgumentError`).

취약:

```elixir
def restore(conn, %{"state" => state}) do
  data = state |> Base.url_decode64!() |> :erlang.binary_to_term()
  render(conn, :show, data: data)
end
```

수정 (우선순위 순):

```elixir
# 1) 신뢰 불가 입력에는 ETF 를 쓰지 않는다 — JSON + 검증
{:ok, data} = Jason.decode(state)

# 2) 서버가 만든 값을 클라이언트에 맡겼다 돌려받는 경우 — 서명 토큰
token = Phoenix.Token.sign(MyAppWeb.Endpoint, "state", data)
{:ok, data} = Phoenix.Token.verify(MyAppWeb.Endpoint, "state", token, max_age: 86_400)

# 3) ETF 가 불가피할 때
data = Plug.Crypto.non_executable_binary_to_term(bin, [:safe])
```

`non_executable_binary_to_term/2` 의 두 번째 인자는 그대로 `:erlang.binary_to_term/2` 에 전달된다.
`[:safe]` 를 빠뜨리면 atom 생성은 막지 못한다. 실패 시 `ArgumentError` 가 나므로 rescue 해서 4xx 로 처리한다.

**오탐 신호:** 같은 애플리케이션만 쓰는 저장소(ETS, 노드 로컬 파일)에서 읽고 외부 쓰기 경로가 없음,
`Phoenix.Token`/`Plug.Crypto.MessageVerifier` 검증을 통과한 뒤의 값(서명 키가 안전하다는 전제).
"우리 DB 에서 읽는다" 는 그 컬럼에 사용자가 쓸 수 있으면 오탐이 아니다.

**테스트 아이디어:** `:erlang.term_to_binary(fn -> :pwned end)` 를 입력으로 보내 4xx 응답(또는 `{:error, _}`)을 확인.
`:erlang.term_to_binary(:"brand_new_atom_#{System.unique_integer()}")` 를 [:safe] 경로에 보내 거부되는지 확인
(인코딩하는 쪽에서 atom 이 이미 생기므로 atom 생성 여부가 아니라 거부 여부를 검사한다).

---

## EXS-RCE-001 — 동적 코드 평가 (Critical)

**무엇:** `Code.eval_string/1,2,3`, `Code.eval_quoted/1,2,3`, `Code.eval_file/1,2`, `Code.compile_string/1,2`,
`EEx.eval_string/1,2,3`, `EEx.eval_file/1,2,3` 에 외부 입력. (Sobelow: `RCE.CodeModule`, `RCE.EEx`)

**BEAM 특유의 위험:** 평가된 코드는 VM 의 모든 권한을 가진다 — `System.cmd`, 파일, 다른 노드로의 RPC,
`:init.stop/0`. 샌드박스는 없다. EEx 템플릿도 `<%= %>` 안에서 임의 Elixir 를 실행한다.

취약:

```elixir
def calculate(conn, %{"expr" => expr}) do
  {result, _binding} = Code.eval_string(expr)
  json(conn, %{result: result})
end

def preview(conn, %{"template" => tpl}) do
  html(conn, EEx.eval_string(tpl, assigns: [user: conn.assigns.current_user]))
end
```

수정 (설계 변경 — 사용자 확인 필요): 실행할 수 있는 동작을 데이터로 제한한다.

```elixir
@ops %{"add" => &+/2, "sub" => &-/2, "mul" => &*/2}

def calculate(conn, %{"op" => op, "a" => a, "b" => b}) do
  with {:ok, fun} <- Map.fetch(@ops, op),
       {a, ""} <- Integer.parse(a),
       {b, ""} <- Integer.parse(b) do
    json(conn, %{result: fun.(a, b)})
  else
    _ -> send_resp(conn, :bad_request, "invalid input")
  end
end
```

템플릿은 컴파일 타임 템플릿(HEEx, `EEx.function_from_file/5`)에 assigns 만 넘긴다. 사용자가 템플릿을 작성해야 하는
기능이면 로직 없는(logic-less) 템플릿 엔진 도입을 제안하고 결정은 사용자에게 맡긴다.

**오탐 신호:** mix task, `config/*.exs`, 매크로·컴파일 타임 코드, `iex` 헬퍼, 개발 전용 모듈(`only: :dev`)에서
리터럴/프로젝트 파일만 평가. 관리자 전용 콘솔이라도 인증 우회 시 RCE 이므로 "실제" 로 두고 심각도만 조정을 논의한다.

**테스트 아이디어:** `expr=System.halt()` 같은 입력이 400 을 반환하는지, 허용된 연산만 동작하는지 확인.

---

## EXS-CMD-001 — OS 명령 주입 (Critical)

**무엇:** `:os.cmd/1,2`, `System.shell/1,2`, `System.cmd("sh" | "bash", ["-c", ...])`, 그리고 실행 파일 이름 자체가
외부 입력인 `System.cmd/3`. (Sobelow: `CI.OS`, `CI.System`)

**BEAM 특유의 위험:** `:os.cmd` 와 `System.shell` 은 항상 셸을 거친다. 명령은 BEAM 사용자 권한으로 실행되며,
release 의 쿠키 파일(`releases/COOKIE`)을 읽으면 클러스터 전체로 확장될 수 있다.

취약:

```elixir
def ping(conn, %{"host" => host}) do
  output = :os.cmd(~c"ping -c 1 #{host}")
  text(conn, List.to_string(output))
end

System.cmd("sh", ["-c", "convert #{upload.path} -resize 200x200 #{out}"])
```

수정: 셸 없이 실행 파일 + 인자 리스트, 입력 검증, 옵션 주입 차단(`--`).

```elixir
def ping(conn, %{"host" => host}) do
  with {:ok, ip} <- :inet.parse_address(String.to_charlist(host)) do
    {output, _status} = System.cmd("ping", ["-c", "1", to_string(:inet.ntoa(ip))])
    text(conn, output)
  else
    _ -> send_resp(conn, :bad_request, "invalid host")
  end
end

System.cmd("convert", [upload.path, "-resize", "200x200", out])
```

`System.cmd/3` 은 셸을 거치지 않으므로 `;`, `|`, `$()` 가 해석되지 않는다. 다만 인자가 `-` 로 시작하면 옵션으로
해석될 수 있으니(argument injection) 형식을 검증하거나 실행 파일이 지원하면 `--` 를 넣는다.
`upload.path` 는 Plug 가 만든 임시 경로라 안전하지만 `upload.filename` 은 공격자가 정한다.

**오탐 신호:** 명령 문자열이 리터럴이고 보간 없음, 보간 값이 컴파일 타임 상수·설정값, 빌드/배포 스크립트·mix task.

**테스트 아이디어:** `host="127.0.0.1; touch /tmp/pwned"` 가 400 이고 파일이 생기지 않는지 확인.

---

## EXS-SQLI-001 — Ecto `fragment` 문자열 보간 (Critical)

**무엇:** `fragment("... #{x} ...")` 처럼 fragment 의 SQL 문자열을 런타임 값으로 조립하는 경우,
그리고 파라미터 바인딩을 우회하는 `identifier(^x)` / `constant(^x)` 에 외부 입력을 넣는 경우.

**배경 (Ecto 3 동작):** Ecto 쿼리 빌더는 fragment 의 첫 인자가 매크로 확장 후 **문자열 리터럴**이 아니면
컴파일 에러를 낸다 ("to prevent SQL injection attacks, fragment(...) does not allow strings to be interpolated...").
따라서 `fragment("lower(#{col})")` 은 보통 **컴파일되지 않는다.** grep/semgrep 이 이 형태를 잡았다면:
1. 컴파일되지 않는 죽은 코드이거나,
2. 매크로가 컴파일 타임 값으로 문자열을 만들어 `unquote` 하는 경우(보통 안전 — 매크로 인자 출처 확인),
3. Ecto 가 아닌 문자열 SQL 빌더 → EXS-SQLI-002 로 재분류.

실제로 런타임 값이 SQL 에 직접 들어가는 경로는 `identifier/1`, `constant/1` (Ecto 3.13+, 이전 버전은 `literal/1`) 이다.
어댑터가 인용(quote)하지만 공격자가 **테이블/컬럼을 선택**하게 되고, 값마다 별도의 prepared statement 가 캐시되어
쿼리 캐시가 무한히 늘어날 수 있다.

취약:

```elixir
# 런타임 컬럼명을 그대로 사용
def search(query, %{"field" => col, "q" => q}) do
  where(query, [u], fragment("lower(?) = ?", field(u, ^String.to_atom(col)), ^q))  # + EXS-ATOM-001
end

from p in Post, select: fragment("? COLLATE ?", p.title, identifier(^params["collation"]))
```

수정: 값은 `?` + `^` 로 바인딩, 식별자는 허용 목록.

```elixir
@searchable %{"name" => :name, "email" => :email}

def search(query, %{"field" => col, "q" => q}) do
  case Map.fetch(@searchable, col) do
    {:ok, field} ->
      where(query, [u], fragment("lower(?)", field(u, ^field)) == ^String.downcase(q))

    :error ->
      query
  end
end

@collations %{"es" => "es_ES", "en" => "en_US"}
collation = Map.get(@collations, params["collation"], "en_US")
from p in Post, select: fragment("? COLLATE ?", p.title, identifier(^collation))
```

LIKE 검색에서 사용자의 `%`, `_` 는 SQL 인젝션은 아니지만 의도치 않은 매칭/풀스캔을 만든다. 필요하면 이스케이프한다.

**오탐 신호:** fragment 문자열이 리터럴이고 모든 값이 `?` + `^` 바인딩, 보간 대상이 모듈 속성·매크로 인자(컴파일 타임).

**테스트 아이디어:** 허용 목록 밖 필드명(`"password_hash"`, `"name; DROP TABLE users"`)이 무시/거부되는지 확인.

---

## EXS-SQLI-002 — `Repo.query` / `Ecto.Adapters.SQL.query` 문자열 보간 (Critical)

**무엇:** `Repo.query/1,2,3`, `Repo.query!`, `Ecto.Adapters.SQL.query/4`, `Ecto.Adapters.SQL.query!/4`,
`Ecto.Adapters.SQL.stream/4` 의 SQL 문자열에 `#{}` 보간 또는 `<>` 연결. (Sobelow: `SQL.Query`, `SQL.Stream`)

**위험:** 원시 SQL 이므로 Ecto 의 보호가 없다. 데이터 유출, 인증 우회, (DB 권한에 따라) 데이터 변조.

취약:

```elixir
def find_by_email(email) do
  Repo.query("SELECT id, name FROM users WHERE email = '#{email}'")
end

def report(sort) do
  Repo.query!("SELECT * FROM orders ORDER BY #{sort}")
end
```

수정: 값은 파라미터, 식별자는 허용 목록 (식별자는 파라미터로 바인딩할 수 없다).

```elixir
def find_by_email(email) do
  Repo.query("SELECT id, name FROM users WHERE email = $1", [email])   # Postgres
  # MySQL(MyXQL) / SQLite: "... WHERE email = ?"
end

# 가능하면 Ecto 쿼리로 바꾼다 — 동적 정렬은 허용 목록 맵 후 키워드 리스트 보간
@sort_fields %{"inserted_at" => :inserted_at, "total" => :total}
@sort_dirs %{"asc" => :asc, "desc" => :desc}

def report(params) do
  field = Map.get(@sort_fields, params["sort"], :inserted_at)
  dir = Map.get(@sort_dirs, params["dir"], :desc)

  Order
  |> order_by(^[{dir, field}])
  |> Repo.all()
end
```

**오탐 신호:** 보간 값이 컴파일 타임 상수(`@table`), 정수로 캐스팅이 끝난 값(`Integer.parse/1` 결과가 `{n, ""}` 일 때만 사용),
마이그레이션 파일(`priv/repo/migrations/`)의 `execute/1`. 정수 캐스팅도 파라미터화로 바꾸는 편이 낫다.

**테스트 아이디어:** `email = "x' OR '1'='1"` 로 호출해 0건(또는 정확히 일치하는 건만)이 반환되는지 확인.

---

## EXS-XSS-001 — 이스케이프 우회 출력 (High)

**무엇:** 템플릿/컴포넌트의 `raw/1` (`Phoenix.HTML.raw/1`), 수동 `{:safe, iodata}` 생성, 그리고 HTML 응답을
직접 만드는 `send_resp/3`·`html/2`·`put_resp_content_type("text/html")` 에 외부 입력.
(Sobelow: `XSS.Raw`, `XSS.SendResp`, `XSS.HTML`, `XSS.ContentType`)

**위험:** HEEx/EEx 는 기본적으로 이스케이프하지만 `raw` 는 그 보호를 끈다. 세션 탈취, LiveView 이벤트 위조,
CSRF 토큰 탈취. LiveView 는 같은 페이지의 소켓으로 사용자 권한 동작을 수행할 수 있어 영향이 크다.

취약:

```heex
<div class="bio">{raw(@user.bio)}</div>
<%= raw @post.body_html %>
```

```elixir
def echo(conn, %{"msg" => msg}) do
  conn |> put_resp_content_type("text/html") |> send_resp(200, "<p>#{msg}</p>")
end
```

수정:

```heex
<%!-- 1) 대부분은 raw 를 지우면 끝 — 자동 이스케이프 --%>
<div class="bio">{@user.bio}</div>

<%!-- 2) HTML 서식이 필요하면 허용 목록 기반 정제 후 출력 --%>
<div class="post">{raw(HtmlSanitizeEx.basic_html(@post.body_html))}</div>
```

```elixir
def echo(conn, %{"msg" => msg}) do
  text(conn, msg)   # 또는 템플릿으로 렌더해서 자동 이스케이프
end
```

`HtmlSanitizeEx` 는 별도 의존성(`{:html_sanitize_ex, "~> 1.4"}`)이므로 추가 전 사용자에게 알린다. 정제는 저장 시점과
출력 시점 중 하나로 정하되, 기존 데이터가 있으면 출력 시점 정제가 안전하다. Markdown 렌더러 출력도 HTML 을
통과시키는 경우가 많으므로 신뢰 입력으로 보지 않는다.

**오탐 신호:** `raw` 인자가 컴파일 타임 문자열, 서버가 생성한 신뢰 HTML(아이콘 SVG 상수, `Phoenix.HTML.Form` 헬퍼 결과),
`Jason.encode!/1` 결과를 `<script type="application/json">` 에 넣는 경우(단, `</script>` 이스케이프 여부 확인 — 실제일 수 있음).

**테스트 아이디어:**

```elixir
test "bio is escaped", %{conn: conn} do
  user = user_fixture(bio: "<script>alert(1)</script>")
  html = conn |> get(~p"/users/#{user}") |> html_response(200)
  refute html =~ "<script>alert(1)</script>"
  assert html =~ "&lt;script&gt;"
end
```

---

## EXS-REDOS-001 — 동적 정규식 (Medium)

**무엇:** `Regex.compile/1,2`, `Regex.compile!/1,2` 에 외부 입력으로 만든 패턴.

**BEAM 특유의 위험:** Elixir `Regex` 는 OTP `:re` (PCRE 계열 백트래킹 엔진)를 쓴다. 매칭은 호출한 프로세스에서
실행되며, 악성 패턴(`(a+)+$`)이나 거대한 입력은 요청당 CPU 를 크게 소모한다. OTP 의 기본 match limit 이 무한 루프는
막지만 그 한도까지 도는 비용은 그대로다. 또한 `Regex.compile!` 은 잘못된 패턴에 예외를 던져 500 을 만든다.
사용자 입력을 패턴으로 쓰면 의도와 다른 매칭(패턴 주입)도 생긴다.

취약:

```elixir
def search(conn, %{"q" => q}) do
  regex = Regex.compile!(q, "i")
  json(conn, Enum.filter(names(), &Regex.match?(regex, &1)))
end
```

수정:

```elixir
@max_query 100

def search(conn, %{"q" => q}) when byte_size(q) <= @max_query do
  needle = String.downcase(q)
  json(conn, Enum.filter(names(), &String.contains?(String.downcase(&1), needle)))
end

def search(conn, _params), do: send_resp(conn, :bad_request, "query too long")

# 정규식이 꼭 필요하면 리터럴로 이스케이프
regex = Regex.compile!(Regex.escape(q), "i")
```

**오탐 신호:** 패턴이 `~r` 시길(sigil), 모듈 속성, 설정 상수에서만 온다. 반대로 **고정 정규식이라도** 중첩 수량자
(`(a+)+`, `(.*a){10}`)를 사용자 입력 전체에 적용하면 실제 위험일 수 있다 — 정적 도구가 놓치므로 눈으로 확인한다.

**테스트 아이디어:** `q = "(a+)+$"` 와 긴 입력에서 응답이 빠르게(예: 100ms 내) 400 또는 정상 결과를 내는지 확인.

---

## EXS-PATH-001 — 경로 조작 (High)

**무엇:** `File.read/write/rm/stream!/cp/rename`, `Plug.Conn.send_file/3,5`, `Phoenix.Controller.send_download/3`,
`Path.join/2` 에 외부 입력으로 만든 경로. (Sobelow: `Traversal.FileModule`, `Traversal.SendFile`, `Traversal.SendDownload`, `Misc.FilePath`)

**위험:** `Path.join/2` 는 `..` 를 정규화하지 않는다. `config/runtime.exs`, release 의 `releases/COOKIE`,
`/etc/passwd` 읽기, 업로드 경로 덮어쓰기로 코드 실행까지 이어질 수 있다.

취약:

```elixir
def download(conn, %{"name" => name}) do
  send_file(conn, 200, Path.join("priv/uploads", name))
end

def save(%Plug.Upload{path: tmp, filename: filename}) do
  File.cp!(tmp, Path.join(uploads_dir(), filename))
end
```

수정:

```elixir
defp uploads_dir, do: Application.app_dir(:my_app, "priv/uploads")

def download(conn, %{"name" => name}) do
  base = uploads_dir()

  with {:ok, rel} <- Path.safe_relative(name, base),
       path = Path.join(base, rel),
       true <- File.regular?(path) do
    send_download(conn, {:file, path})
  else
    _ -> send_resp(conn, :not_found, "not found")
  end
end

@allowed_ext ~w(.png .jpg .pdf)

def save(%Plug.Upload{path: tmp, filename: filename}) do
  ext = filename |> Path.extname() |> String.downcase()

  if ext in @allowed_ext do
    stored = Ecto.UUID.generate() <> ext     # 저장 이름은 서버가 만든다
    File.cp!(tmp, Path.join(uploads_dir(), stored))
    {:ok, stored}
  else
    {:error, :unsupported_type}
  end
end
```

`Path.safe_relative/2` (Elixir 1.14+) 는 절대 경로, 기준 디렉터리 위로 올라가는 `..`, 기준 밖을 가리키는 심볼릭 링크를
거부하고 `{:ok, relative}` 또는 `:error` 를 반환한다. 1.14 미만이면 `Path.expand(Path.join(base, name))` 결과가
`Path.expand(base) <> "/"` 로 시작하는지 확인한다. `Application.app_dir/2` 는 release 경로가 컴파일 시점과 다를 수 있으므로
모듈 속성이 아닌 함수로 호출한다.

**오탐 신호:** 경로가 리터럴·설정값, 정수로 캐스팅된 ID 로만 구성(`"#{id}.png"` 에서 `id` 가 이미 integer),
서버가 생성한 UUID 파일명, `Plug.Upload.path` (Plug 가 만든 임시 파일).

**테스트 아이디어:** `name=../../config/runtime.exs`, `name=/etc/passwd` 가 404/400 이고 정상 파일은 200 인지 확인.

---

## EXS-CFG-001 — 비밀값 하드코딩 (High)

**무엇:** `config/config.exs`, `config/prod.exs` 등 커밋되는 설정에 `secret_key_base`, DB 비밀번호, API 키, 토큰이
리터럴로 있는 경우. (Sobelow: `Config.Secrets`)

**위험:** `secret_key_base` 가 유출되면 세션 쿠키·`Phoenix.Token`·서명 쿠키를 위조할 수 있다 (계정 탈취).
git 히스토리에 남으므로 파일에서 지워도 **교체(rotate)가 필요**하다.

취약:

```elixir
# config/prod.exs
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: "kq3...실제값..."
```

수정:

```elixir
# config/runtime.exs
if config_env() == :prod do
  config :my_app, MyAppWeb.Endpoint,
    secret_key_base: System.fetch_env!("SECRET_KEY_BASE")

  config :my_app, MyApp.Repo,
    url: System.fetch_env!("DATABASE_URL")
end
```

새 값은 `mix phx.gen.secret` 으로 만든다. 교체 시 기존 세션이 모두 무효화된다는 점을 사용자에게 알린다.
보고서에는 비밀값 원문을 쓰지 않는다.

**오탐 신호:** `config/dev.exs`, `config/test.exs` 의 생성기 기본값(개발/테스트 전용), `signing_salt`·`encryption_salt`
(salt 는 비밀이 아니며 Phoenix 생성기가 endpoint 의 `@session_options` 에 리터럴로 둔다 — Low 로 낮추거나 오탐),
`System.get_env("X") || raise ...` 패턴, 빈 문자열/플레이스홀더.

**테스트 아이디어:** 해당 없음. `MIX_ENV=prod mix compile` 이 비밀 없이 성공하고 런타임에 `System.fetch_env!/1` 가
누락을 알리는지 확인.

---

## EXS-CFG-002 — CSRF / 보안 헤더 누락 (Medium)

**무엇:** router 의 브라우저 파이프라인(`:fetch_session` 을 쓰는 파이프라인)에 `plug :protect_from_forgery` 또는
`plug :put_secure_browser_headers` 가 없음. (Sobelow: `Config.CSRF`, `Config.Headers`, `Config.CSP`, `Config.CSRFRoute`)

**위험:** 쿠키 세션을 쓰는 상태 변경 요청을 다른 사이트가 위조(CSRF), 클릭재킹, MIME 스니핑.

수정 예시와 CSP·`check_origin`(LiveView/Channel, Sobelow `Config.CSWH`) 은 [phoenix-config.md](phoenix-config.md) 참고.

**오탐 신호:** API 전용 파이프라인(`:api`, 세션 쿠키 없음, Bearer 토큰 인증), 웹훅 수신 경로(서명 검증으로 대체).

**테스트 아이디어:** 응답에 `x-frame-options`/`content-security-policy` 헤더가 있는지 확인. CSRF 는
`Phoenix.ConnTest.build_conn/0` 이 기본으로 CSRF 검사를 건너뛰게 하므로
`Plug.Conn.put_private(conn, :plug_skip_csrf_protection, false)` 를 넣은 뒤 토큰 없는 POST 가
`assert_error_sent 403, fn -> ... end` 인지 확인한다.

---

## EXS-CFG-003 — HTTPS 강제 없음 (Low)

**무엇:** prod 설정에 endpoint `force_ssl` 이 없음. (Sobelow: `Config.HTTPS`, `Config.HSTS`)

**위험:** 다운그레이드/중간자 공격, `secure` 플래그 없는 쿠키 전송. 프록시/로드밸런서에서 이미 리다이렉트·HSTS 를
처리하면 영향이 작다 (기본 Low 인 이유).

수정: `config/prod.exs` 에 `force_ssl: [hsts: true]` (컴파일 타임 설정 — runtime.exs 에 두면 적용되지 않는다).
TLS 종료 프록시 뒤라면 `rewrite_on: [:x_forwarded_proto]`. 세부는 [phoenix-config.md](phoenix-config.md).

**오탐 신호:** 인프라 레벨(로드밸런서, Ingress, CDN)에서 HTTPS 리다이렉트와 HSTS 를 설정했다는 근거가 있음
— 사용자에게 확인 후 오탐 사유로 기록.

**테스트 아이디어:** `MIX_ENV=prod` 에서 `http://` 요청이 301 로 `https://` 리다이렉트되는지(스테이징에서 확인).

---

## EXS-DEP-001 — 알려진 취약점이 있는 의존성 (권고 심각도)

**무엇:** `mix deps.audit` (mix_audit, Elixir 생태계 보안 권고 DB) 또는 `osv-scanner` 가 `mix.lock` 에서 찾은 취약 버전.

**위험:** 권고(advisory)마다 다르다. 심각도는 권고에 적힌 값을 쓰고, 해당 기능을 실제로 쓰는지로 도달성을 판단한다.

수정:

```bash
mix hex.outdated                 # 현재/최신 버전 확인
mix deps.update plug             # 요구 사항 범위 안에서 최소 업그레이드 (전이 의존성도 가능)
mix deps.audit                   # 재확인
```

`mix.exs` 의 요구 사항(`~> 1.2.0` 등)이 패치 버전을 막으면 요구 사항 완화가 필요하다. **메이저 업그레이드나
호환성 깨짐이 예상되면 사용자 확인 후 진행**한다. 권고 ID(CVE/GHSA)는 도구 출력에 있는 값만 그대로 인용한다.

**오탐 신호:** 취약 함수/기능을 쓰지 않음(권고의 영향 범위 확인), dev/test 전용 의존성(`only: :dev`) —
그래도 업그레이드가 쉬우면 고친다.

**테스트 아이디어:** 전체 `mix test`, 해당 라이브러리를 쓰는 경로의 통합 테스트.

---

## EXS-DEP-002 — Retired 패키지 (Medium)

**무엇:** `mix hex.audit` 가 보고한 retire 된 패키지 버전. Hex 의 retire 사유는 `security`, `invalid`, `deprecated`,
`renamed`, `other` 중 하나다.

**위험:** 사유가 `security` 면 High 로 올린다. `invalid` 는 깨진 릴리스, `deprecated`/`renamed` 는 유지보수 중단 신호.

수정: 출력에 안내된 대체 버전으로 `mix deps.update <pkg>`. `renamed` 면 새 패키지로 교체 (코드 변경이 필요하면 사용자 확인).

**오탐 신호:** 없음에 가깝다. 업그레이드할 수 없는 사유가 있으면 "남은 항목" 에 기록한다.

**테스트 아이디어:** 전체 `mix test`.
