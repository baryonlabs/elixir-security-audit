defmodule VulnApp.Reports do
  @moduledoc "Order reports via raw SQL."

  alias VulnApp.Repo

  def orders_by_status(status) when is_binary(status) do
    # VULN: EXS-SQLI-002 (user input interpolated into a raw SQL string)
    Ecto.Adapters.SQL.query(Repo, "SELECT id, total FROM orders WHERE status = '#{status}'", [])
  end

  def orders_by_status_safe(status) when is_binary(status) do
    # SAFE: positional parameter, value passed separately
    Ecto.Adapters.SQL.query(Repo, "SELECT id, total FROM orders WHERE status = $1", [status])
  end

  @doc "Ecto query builder (safe pinned parameter) - kept to show the idiomatic form."
  def recent_orders_query(min_total) do
    import Ecto.Query
    from(o in "orders", where: fragment("? >= ?", o.total, ^min_total), select: o.id)
  end
end
