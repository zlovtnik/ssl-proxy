class WirelessDeviceInventory < SyncRecord
  self.table_name = "v_wireless_device_inventory"
  self.primary_key = "source_mac"

  scope :recent, -> { order(last_occurred_at: :desc) }
  scope :search, ->(query) {
    query.blank? ? none : where(
      "source_mac ILIKE :q OR COALESCE(location_id, '') ILIKE :q OR COALESCE(sensor_id, '') ILIKE :q OR COALESCE(ssid, '') ILIKE :q OR COALESCE(destination_bssid, '') ILIKE :q OR COALESCE(ip_addresses, '') ILIKE :q OR COALESCE(hostnames, '') ILIKE :q OR COALESCE(services, '') ILIKE :q OR COALESCE(dns_names, '') ILIKE :q OR COALESCE(registered_username, '') ILIKE :q OR COALESCE(display_name, '') ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }
end
