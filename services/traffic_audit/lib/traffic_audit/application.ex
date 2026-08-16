defmodule TrafficAudit.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children =
      if Application.get_env(:traffic_audit, :persistence, :log) == :repo do
        # Option A path: a live TiDB connection is only ever started when
        # persistence explicitly asks for the Repo. Default (:log) never
        # attempts a database connection — the escript must boot offline.
        [TrafficAudit.Repo]
      else
        []
      end

    opts = [strategy: :one_for_one, name: TrafficAudit.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
