class NetworkClientsController < ApplicationController
  def index
    @payload = Rails.cache.fetch("network_clients:index", expires_in: 30.seconds) do
      rows = NetworkClient.recent.select(:ssid, :client_mac, :known_bssid, :probe_count, :first_seen, :last_seen).as_json
      { rows: rows, fetchedAt: Time.current.iso8601 }
    end

    respond_to do |format|
      format.html
      format.json { render json: @payload }
    end
  end
end
