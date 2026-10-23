# Annotated test file for skills/elixir-security-audit/rules/elixir-security.yml
# Annotation comments: "ruleid" means the next line must match, "ok" means it must not.
# `opengrep test` ignores `paths: include`, so the generic template rule
# exs-xss-001-template also fires on raw/1 lines here; real scans restrict it
# to *.heex/*.eex.
# This code is intentionally insecure and is never compiled.
defmodule ExsRuleTest do
  import Ecto.Query

  # ------------------------------------------------------------ ATOM-001
  def atom_1(input) do
    # ruleid: exs-atom-001
    String.to_atom(input)
  end

  def atom_1_pipe(input) do
    # ruleid: exs-atom-001
    input |> String.to_atom()
  end

  def atom_1_interp(input) do
    # ruleid: exs-atom-001
    String.to_atom("sort_#{input}")
  end

  def atom_1_literal do
    # ok: exs-atom-001
    String.to_atom("fixed")
  end

  def atom_1_safe(input) do
    # ok: exs-atom-001
    String.to_existing_atom(input)
  end

  def atom_1_list(chars) do
    # ruleid: exs-atom-001-list
    List.to_atom(chars)
  end

  # ------------------------------------------------------------ ATOM-002
  def atom_2(body) do
    # ruleid: exs-atom-002
    Jason.decode(body, keys: :atoms)
  end

  def atom_2_bang(body) do
    # ruleid: exs-atom-002
    Jason.decode!(body, strict: true, keys: :atoms)
  end

  def atom_2_existing(body) do
    # ok: exs-atom-002
    Jason.decode!(body, keys: :atoms!)
  end

  def atom_2_strings(body) do
    # ok: exs-atom-002
    Jason.decode!(body)
  end

  # ------------------------------------------------------------ DESER-001
  def deser(bin) do
    # ruleid: exs-deser-001
    :erlang.binary_to_term(bin)
  end

  def deser_safe_opt(bin) do
    # ruleid: exs-deser-001-opts
    :erlang.binary_to_term(bin, [:safe])
  end

  def deser_plug(bin) do
    # ok: exs-deser-001, exs-deser-001-opts
    Plug.Crypto.non_executable_binary_to_term(bin, [:safe])
  end

  # ------------------------------------------------------------ RCE-001
  def rce_string(src) do
    # ruleid: exs-rce-001
    Code.eval_string(src)
  end

  def rce_bindings(src, b) do
    # ruleid: exs-rce-001
    Code.eval_string(src, b)
  end

  def rce_quoted(ast) do
    # ruleid: exs-rce-001
    Code.eval_quoted(ast)
  end

  def rce_eex(tpl, assigns) do
    # ruleid: exs-rce-001
    EEx.eval_string(tpl, assigns: assigns)
  end

  def rce_eex_file(path) do
    # ruleid: exs-rce-001
    EEx.eval_file(path)
  end

  def rce_literal do
    # ok: exs-rce-001
    Code.eval_string("1 + 1")
  end

  # ------------------------------------------------------------ CMD-001
  def cmd_os(host) do
    # ruleid: exs-cmd-001
    :os.cmd(String.to_charlist("ping -c 1 " <> host))
  end

  def cmd_sh(host) do
    # ruleid: exs-cmd-001
    System.cmd("sh", ["-c", "ping -c 1 #{host}"])
  end

  def cmd_bash_opts(script) do
    # ruleid: exs-cmd-001
    System.cmd("bash", ["-c", script], stderr_to_stdout: true)
  end

  def cmd_shell(cmd) do
    # ruleid: exs-cmd-001
    System.shell(cmd)
  end

  def cmd_direct(host) do
    # ok: exs-cmd-001
    System.cmd("ping", ["-c", "1", host])
  end

  # ------------------------------------------------------------ SQLI-001
  def sqli_fragment(name) do
    # ruleid: exs-sqli-001
    from(u in "users", where: fragment("lower(name) = '#{name}'"), select: u.id)
  end

  def sqli_fragment_args(col, name) do
    # ruleid: exs-sqli-001
    from(u in "users", where: fragment("#{col} = ?", ^name), select: u.id)
  end

  def sqli_fragment_safe(name) do
    # ok: exs-sqli-001
    from(u in "users", where: fragment("lower(?) = ?", u.name, ^name), select: u.id)
  end

  # ------------------------------------------------------------ SQLI-002
  def sqli_query(id) do
    # ruleid: exs-sqli-002
    MyApp.Repo.query("SELECT * FROM users WHERE id = #{id}")
  end

  def sqli_query_bang(id) do
    # ruleid: exs-sqli-002
    Repo.query!("DELETE FROM users WHERE id = #{id}", [])
  end

  def sqli_adapter(id) do
    # ruleid: exs-sqli-002
    Ecto.Adapters.SQL.query(MyApp.Repo, "SELECT * FROM users WHERE id = #{id}", [])
  end

  def sqli_via_var(id) do
    sql = "SELECT * FROM users WHERE id = #{id}"
    # ruleid: exs-sqli-002
    Repo.query!(sql, [])
  end

  def sqli_param(id) do
    # ok: exs-sqli-002
    Repo.query("SELECT * FROM users WHERE id = $1", [id])
  end

  # ------------------------------------------------------------ XSS-001
  def xss(bio) do
    # ruleid: exs-xss-001, exs-xss-001-template
    raw(bio)
  end

  def xss_qualified(bio) do
    # ruleid: exs-xss-001, exs-xss-001-template
    Phoenix.HTML.raw(bio)
  end

  def xss_escaped(bio) do
    # ok: exs-xss-001
    Phoenix.HTML.html_escape(bio)
  end

  # ------------------------------------------------------------ REDOS-001
  def redos(pattern) do
    # ruleid: exs-redos-001
    Regex.compile(pattern)
  end

  def redos_bang(pattern) do
    # ruleid: exs-redos-001
    Regex.compile!(pattern, "i")
  end

  def redos_literal do
    # ok: exs-redos-001
    Regex.compile!("^[a-z]+$")
  end

  def redos_escaped(term) do
    # ok: exs-redos-001
    Regex.compile!(Regex.escape(term))
  end

  def redos_sigil(term) do
    # ruleid: exs-redos-001-sigil
    String.match?("abc", ~r/^#{term}$/)
  end

  def redos_sigil_escaped(term) do
    # ok: exs-redos-001-sigil
    String.match?("abc", ~r/^#{Regex.escape(term)}$/)
  end
end

defmodule ExsRuleTest.FileController do
  use Phoenix.Controller

  # ------------------------------------------------------------ PATH-001
  def show(conn, %{"name" => name}) do
    # ruleid: exs-path-001
    File.read!(name)
    send_resp(conn, 200, "ok")
  end

  def download(conn, params) do
    rel = params["file"]
    # ruleid: exs-path-001
    full = Path.join("/srv/uploads", rel)
    # ruleid: exs-path-001
    send_file(conn, 200, full)
  end

  def delete(conn, _params) do
    # ruleid: exs-path-001
    File.rm!(conn.params["path"])
    send_resp(conn, 204, "")
  end

  def export(conn, %{"name" => name}) do
    # ruleid: exs-path-001
    send_download(conn, {:file, name})
  end

  def safe(conn, %{"name" => name}) do
    case Path.safe_relative(name) do
      {:ok, rel} ->
        # ok: exs-path-001
        send_file(conn, 200, Path.join(["/srv/uploads", rel]))

      :error ->
        send_resp(conn, 400, "bad path")
    end
  end

  def basename(conn, %{"name" => name}) do
    # ok: exs-path-001
    File.read!(Path.basename(name))
    send_resp(conn, 200, "ok")
  end

  def static(conn, _params) do
    # ok: exs-path-001
    File.read!("priv/static/robots.txt")
    send_resp(conn, 200, "ok")
  end
end

defmodule ExsRuleTest.FileLive do
  use Phoenix.LiveView

  def handle_event("open", %{"path" => path}, socket) do
    # ruleid: exs-path-001
    {:ok, body} = File.read(path)
    {:noreply, assign(socket, body: body)}
  end
end

defmodule ExsRuleTest.Uploads do
  @upload_dir "priv/uploads"

  # PATH-001 across a module boundary: the controller passes params here.
  def read_upload(name) when is_binary(name) do
    # ruleid: exs-path-001-param
    File.read!(Path.join(@upload_dir, name))
  end

  # ruleid: exs-path-001-param
  defp purge(dir, name), do: File.rm_rf!(Path.join(dir, name))

  def read_upload_safe(name) when is_binary(name) do
    case Path.safe_relative(name, @upload_dir) do
      # ok: exs-path-001-param
      {:ok, rel} -> File.read(Path.join(@upload_dir, rel))
      :error -> {:error, :invalid_path}
    end
  end

  def read_fixed do
    # ok: exs-path-001-param
    File.read!(Path.join(@upload_dir, "index.txt"))
  end

  def show(conn, %{"name" => name}) do
    # ok: exs-path-001-param
    # ruleid: exs-path-001
    File.read!(name)
    {conn, purge(@upload_dir, name)}
  end
end
