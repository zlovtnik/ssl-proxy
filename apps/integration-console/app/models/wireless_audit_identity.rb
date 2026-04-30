class WirelessAuditIdentity < SyncRecord
  self.table_name = "v_wireless_device_inventory"
  self.primary_key = "source_mac"

  scope :recent, -> { order(last_occurred_at: :desc) }
  scope :search, ->(query) {
    query.blank? ? none : where(
      "source_mac ILIKE :q OR bssid ILIKE :q OR destination_bssid ILIKE :q OR ssid ILIKE :q OR username ILIKE :q OR registered_username ILIKE :q OR device_fingerprint ILIKE :q OR wps_device_name ILIKE :q OR wps_manufacturer ILIKE :q OR wps_model_name ILIKE :q OR COALESCE(ip_addresses, '') ILIKE :q OR COALESCE(services, '') ILIKE :q OR COALESCE(hostname, '') ILIKE :q OR COALESCE(display_name, '') ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }
end
