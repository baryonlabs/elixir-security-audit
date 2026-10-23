defmodule VulnAppWeb.DownloadController do
  use VulnAppWeb, :controller

  def show(conn, %{"file" => file}) do
    body = VulnApp.Files.read_upload(file)

    conn
    |> put_resp_content_type("application/octet-stream")
    |> send_resp(200, body)
  end
end
