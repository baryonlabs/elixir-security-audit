import Config

# VULN: EXS-CFG-003 (prod endpoint config has no force_ssl / HSTS)
config :vuln_app, VulnAppWeb.Endpoint,
  url: [host: "vuln-app.example.com", port: 80],
  http: [ip: {0, 0, 0, 0}, port: 4000],
  # VULN: EXS-CFG-001 (secret_key_base hardcoded in source instead of runtime.exs + System.fetch_env!/1)
  secret_key_base: "pY3kQ8vXr2mN7tB4wZ9cL1sD6fH0jK5gA8eR3uI7oP2yT6nM4bV9xC1zQ5wE8rT0",
  server: true

config :vuln_app, VulnApp.Repo,
  url: "ecto://postgres:postgres@db/vuln_app_prod",
  pool_size: 10

config :logger, level: :info
