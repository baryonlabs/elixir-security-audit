defmodule VulnAppWeb.CommentController do
  use VulnAppWeb, :controller

  def preview(conn, %{"comment" => comment}) do
    html =
      %{comment: comment}
      |> VulnAppWeb.CommentHTML.preview()
      |> Phoenix.HTML.Safe.to_iodata()

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, html)
  end
end
