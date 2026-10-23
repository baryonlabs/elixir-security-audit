# dev.exs is excluded by exs-cfg-001 (mix phx.new generates throwaway secrets here).
import Config

# ok: exs-cfg-001
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: "dev-only-secret-dev-only-secret-dev-only-secret-dev-only-secret00"
