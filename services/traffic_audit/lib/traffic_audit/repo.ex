defmodule TrafficAudit.Repo do
  @moduledoc """
  `Ecto.Repo` client for the `traffic_audit` TiDB domain.

  This app uses Ecto **as a client only** — it does **not** apply canonical DDL
  (the `transport_scores` table is provisioned under `sql/tidb/traffic_audit/`
  by the schema executor, per the repo's TiDB governance). The `save` Effect step
  persists through `Interpreter`, which is the sole module that may touch
  `Ecto.Repo`.
  """

  use Ecto.Repo,
    otp_app: :traffic_audit,
    adapter: Ecto.Adapters.MyXQL
end
