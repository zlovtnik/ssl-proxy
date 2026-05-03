class NetworkClient < SyncRecord
  self.table_name = "network_clients"

  scope :recent, ->(limit = 500) { order(last_seen: :desc).limit(limit) }
end
