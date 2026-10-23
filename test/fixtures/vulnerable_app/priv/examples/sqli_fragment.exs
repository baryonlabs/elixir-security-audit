# NOT COMPILED. This file lives outside elixirc_paths on purpose.
#
# Ecto rejects interpolated strings in fragment/1 at compile time
# ("to prevent SQL injection attacks, fragment(...) does not allow strings
# to be interpolated as the first argument"), so EXS-SQLI-001 cannot exist in
# code that compiles. Scanners still flag it statically because it shows up in
# snippets, generated code, and Ecto forks. Kept here for detection only.

defmodule VulnApp.Examples.SqliFragment do
  import Ecto.Query

  def by_name(name) do
    # VULN: EXS-SQLI-001 (string interpolation inside fragment/1)
    from(u in "users", where: fragment("lower(name) = '#{name}'"), select: u.id)
  end
end
