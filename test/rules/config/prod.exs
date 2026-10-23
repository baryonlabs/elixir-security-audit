# Annotated test file for EXS-CFG-001 (path matters: rules use **/prod.exs).
import Config

# ruleid: exs-cfg-001
config :my_app, MyAppWeb.Endpoint,
  url: [host: "example.com", port: 443],
  secret_key_base: "Zx9lQh2v3mJ0f1u8yX7cR4tK6pN5wB2aE3dG8hL1sQ0vT9yU4iO7pA6sD5fG3hJ2"

# ruleid: exs-cfg-001
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: System.get_env("SECRET_KEY_BASE") || "fallback-secret-in-repo"

# ok: exs-cfg-001
config :my_app, MyAppWeb.Endpoint,
  secret_key_base: System.fetch_env!("SECRET_KEY_BASE")

# ruleid: exs-cfg-001-salt
config :my_app, MyAppWeb.Endpoint,
  live_view: [foo: 1],
  signing_salt: "abc123de"
