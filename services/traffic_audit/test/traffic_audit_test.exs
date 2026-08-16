defmodule TrafficAuditTest do
  use ExUnit.Case, async: true

  # Smoke test: the application module roots and the escript main module must
  # compile into loadable modules (replaces the `mix new` scaffold test).
  test "application and CLI modules are defined" do
    assert Code.ensure_loaded?(TrafficAudit.Application)
    assert Code.ensure_loaded?(TrafficAudit.CLI)
  end
end
