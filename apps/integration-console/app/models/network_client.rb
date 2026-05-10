class NetworkClient < SyncRecord
  self.table_name = "network_clients"

  scope :recent, ->(limit = 500) { order(last_seen: :desc, client_mac: :asc, ssid: :asc).limit(limit) }
  scope :search, ->(query) {
    sanitized = ActiveRecord::Base.sanitize_sql_like(query.to_s.strip)
    sanitized.blank? ? all : where("ssid ILIKE ? OR client_mac ILIKE ? OR known_bssid ILIKE ?", "%#{sanitized}%", "%#{sanitized}%", "%#{sanitized}%")
  }
end
