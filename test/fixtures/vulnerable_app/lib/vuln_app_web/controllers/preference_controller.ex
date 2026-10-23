defmodule VulnAppWeb.PreferenceController do
  use VulnAppWeb, :controller

  def show(conn, _params) do
    conn = fetch_cookies(conn)

    prefs =
      case conn.cookies["prefs"] do
        nil -> %{theme: "light"}
        cookie -> VulnApp.Preferences.decode(cookie)
      end

    text(conn, inspect(prefs))
  end
end
