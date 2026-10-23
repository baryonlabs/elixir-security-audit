defmodule VulnApp.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children =
      repo_children() ++
        [
          {Phoenix.PubSub, name: VulnApp.PubSub},
          VulnAppWeb.Endpoint
        ]

    Supervisor.start_link(children, strategy: :one_for_one, name: VulnApp.Supervisor)
  end

  @impl true
  def config_change(changed, _new, removed) do
    VulnAppWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp repo_children do
    if Application.get_env(:vuln_app, :start_repo, true), do: [VulnApp.Repo], else: []
  end
end
