defmodule VulnAppWeb.RoutesTest do
  use VulnAppWeb.ConnCase, async: true

  # These tests document that each vulnerable sink is reachable from HTTP input.

  test "GET /products sorts by user-chosen field (EXS-ATOM-001)", %{conn: conn} do
    body = conn |> get("/products?sort=price") |> json_response(200)
    assert [%{"name" => "bolt"} | _] = body["products"]
  end

  test "GET /calc evaluates the formula (EXS-RCE-001)", %{conn: conn} do
    assert conn |> get("/calc?formula=1%2B2") |> response(200) == "3"
  end

  test "GET /search compiles the user's regex (EXS-REDOS-001)", %{conn: conn} do
    assert %{"matches" => ["crate"]} = conn |> get("/search?pattern=^c") |> json_response(200)
  end

  test "GET /download reads from the upload dir (EXS-PATH-001)", %{conn: conn} do
    assert conn |> get("/download?file=readme.txt") |> response(200) == "hello from uploads\n"
  end

  test "GET /download follows ../ out of the upload dir (EXS-PATH-001)", %{conn: conn} do
    assert conn |> get("/download?file=../../mix.exs") |> response(200) =~ "VulnApp.MixProject"
  end

  test "GET /comments/preview renders unescaped HTML (EXS-XSS-001)", %{conn: conn} do
    body = conn |> get("/comments/preview?comment=<script>alert(1)</script>") |> response(200)
    assert body =~ "<script>alert(1)</script>"
  end

  test "banner is trusted static markup" do
    assert Phoenix.HTML.safe_to_string(VulnAppWeb.CommentHTML.banner()) =~ "<strong>"
  end

  test "GET /preferences decodes the prefs cookie (EXS-DESER-001)", %{conn: conn} do
    cookie = VulnApp.Preferences.encode(%{theme: "dark"})

    body =
      conn
      |> put_req_cookie("prefs", cookie)
      |> get("/preferences")
      |> response(200)

    assert body == ~s(%{theme: "dark"})
  end

  test "browser responses lack secure headers (EXS-CFG-002)", %{conn: conn} do
    conn = get(conn, "/products")
    assert get_resp_header(conn, "x-frame-options") == []
  end

  test "POST /api/import decodes with atom keys (EXS-ATOM-002)", %{conn: conn} do
    conn = post(conn, "/api/import", %{"payload" => ~s({"brand_new_key":1})})
    assert %{"imported" => %{"brand_new_key" => 1}} = json_response(conn, 200)
  end

  test "POST /api/feeds parses XML with sweet_xml 0.6.6 (EXS-DEP-001)", %{conn: conn} do
    xml = "<rss><item><title>hi</title></item></rss>"

    assert %{"titles" => ["hi"]} =
             conn |> post("/api/feeds", %{"xml" => xml}) |> json_response(200)
  end
end
