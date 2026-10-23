import Config

config :vuln_app,
  ecto_repos: [VulnApp.Repo]

config :vuln_app, VulnAppWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [html: VulnAppWeb.ErrorHTML], layout: false],
  pubsub_server: VulnApp.PubSub

config :logger, :console, format: "$time $metadata[$level] $message\n"

config :phoenix, :json_library, Jason

import_config "#{config_env()}.exs"
