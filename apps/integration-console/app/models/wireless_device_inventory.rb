class WirelessDeviceInventory < SyncRecord
  self.table_name = "v_wireless_device_inventory"
  self.primary_key = "inventory_key"

  scope :recent, -> { where(last_seen: 7.days.ago..).order(last_seen: :desc) }
  scope :search, ->(query) {
    next none if query.blank?

    where(
      "source_mac ILIKE :q OR COALESCE(location_id, '') ILIKE :q OR COALESCE(ssid, '') ILIKE :q OR COALESCE(destination_bssid, '') ILIKE :q OR COALESCE(ip_addresses, '') ILIKE :q OR COALESCE(hostnames, '') ILIKE :q OR COALESCE(services, '') ILIKE :q OR COALESCE(dns_names, '') ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }
end
