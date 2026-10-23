defmodule VulnApp.MixProject do
  use Mix.Project

  # DO NOT DEPLOY: intentionally vulnerable fixture for elixir-security-audit.

  def project do
    [
      app: :vuln_app,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {VulnApp.Application, []},
      extra_applications: [:logger, :runtime_tools, :xmerl]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.7.14"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_view, "~> 1.0"},
      {:bandit, "~> 1.5"},
      {:jason, "~> 1.4"},
      {:ecto_sql, "~> 3.12"},
      {:postgrex, ">= 0.0.0"},
      # VULN: EXS-DEP-001 (sweet_xml <= 0.6.6, CVE-2019-15160 inline DTD XML bomb; patched >= 0.7.0)
      {:sweet_xml, "0.6.6"},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end
end
