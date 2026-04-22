class WirelessAuditIdentity < SyncRecord
  self.table_name = "v_wireless_audit_with_devices"
  self.primary_key = "dedupe_key"

  scope :recent, -> { order(observed_at: :desc) }
  scope :search, ->(query) {
    where(
      "source_mac ILIKE :q OR bssid ILIKE :q OR ssid ILIKE :q OR username ILIKE :q OR registered_username ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }
end
