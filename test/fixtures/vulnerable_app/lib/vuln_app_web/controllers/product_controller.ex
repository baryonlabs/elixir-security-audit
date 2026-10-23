defmodule VulnAppWeb.ProductController do
  use VulnAppWeb, :controller

  alias VulnApp.Catalog

  def index(conn, params) do
    products = Catalog.sort_products(params["sort"] || "name")
    json(conn, %{products: products})
  end
end
