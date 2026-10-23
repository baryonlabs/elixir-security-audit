import Config

config :vuln_app, VulnApp.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "vuln_app_dev",
  pool_size: 5

config :vuln_app, VulnAppWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4000],
  check_origin: false,
  debug_errors: true,
  secret_key_base: String.duplicate("dev-only-not-a-secret-", 4)

config :logger, :console, format: "[$level] $message\n"
