class NetworkClientsController < ApplicationController
  def index
    @payload = Rails.cache.fetch("network_clients:index", expires_in: 30.seconds) do
      rows = SyncRecord.connection.exec_query(<<~SQL).to_a
        SELECT ssid, client_mac, known_bssid, probe_count,
               first_seen, last_seen
        FROM network_clients
        ORDER BY last_seen DESC
        LIMIT 500
      SQL
      { rows: rows, fetchedAt: Time.current.iso8601 }
    end

    respond_to do |format|
      format.html
      format.json { render json: @payload }
    end
  end
end
