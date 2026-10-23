defmodule VulnAppWeb.ApiController do
  use VulnAppWeb, :controller

  def import(conn, %{"payload" => payload}) do
    {:ok, data} = VulnApp.Importer.import_payload(payload)
    json(conn, %{imported: data})
  end

  def thumbnail(conn, %{"filename" => filename}) do
    {output, status} = VulnApp.Thumbnails.generate(filename)
    json(conn, %{status: status, output: output})
  end

  def orders(conn, %{"status" => status}) do
    {:ok, result} = VulnApp.Reports.orders_by_status(status)
    json(conn, %{rows: result.rows})
  end

  def feed(conn, %{"xml" => xml}) do
    json(conn, %{titles: VulnApp.Feeds.item_titles(xml)})
  end
end
