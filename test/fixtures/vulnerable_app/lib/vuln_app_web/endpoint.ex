defmodule VulnAppWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :vuln_app

  @session_options [
    store: :cookie,
    key: "_vuln_app_key",
    signing_salt: "Xq3vL9pz",
    same_site: "Lax"
  ]

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, @session_options
  plug VulnAppWeb.Router
end
