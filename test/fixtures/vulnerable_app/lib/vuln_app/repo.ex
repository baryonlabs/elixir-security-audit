defmodule VulnApp.Repo do
  use Ecto.Repo,
    otp_app: :vuln_app,
    adapter: Ecto.Adapters.Postgres
end
