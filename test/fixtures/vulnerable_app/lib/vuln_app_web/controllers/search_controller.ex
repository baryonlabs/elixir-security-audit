defmodule VulnAppWeb.SearchController do
  use VulnAppWeb, :controller

  def index(conn, %{"pattern" => pattern}) do
    names = Enum.map(VulnApp.Catalog.list_products(), & &1.name)
    json(conn, %{matches: VulnApp.Search.filter(names, pattern)})
  end
end
