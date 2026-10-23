import Config

# Tests never touch a database: the Repo is configured but not started.
config :vuln_app, start_repo: false

config :vuln_app, VulnApp.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "vuln_app_test",
  pool: Ecto.Adapters.SQL.Sandbox

config :vuln_app, VulnAppWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: String.duplicate("test-only-not-a-secret-", 4),
  server: false

config :logger, level: :warning
