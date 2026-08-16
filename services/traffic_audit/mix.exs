defmodule TrafficAudit.MixProject do
  use Mix.Project

  def project do
    [
      app: :traffic_audit,
      version: "0.1.0",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      escript: [main_module: TrafficAudit.CLI, name: "traffic-audit"],
      build_per_environment: false,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {TrafficAudit.Application, []}
    ]
  end

  defp deps do
    [
      {:ecto_sql, "~> 3.14"},
      {:myxql, "~> 0.9.0"},
      {:jason, "~> 1.4"},

      # Dev / test / lint only — excluded from the escript build.
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:stream_data, "~> 1.4", only: :test, runtime: false},
      {:ex_doc, "~> 0.40.3", only: [:dev], runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
