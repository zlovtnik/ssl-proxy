class WirelessAuditIdentity < SyncRecord
  self.table_name = "v_wireless_audit_with_devices"
  self.primary_key = "dedupe_key"

  scope :recent, -> { where(observed_at: 7.days.ago..).order(observed_at: :desc) }
  scope :search, ->(query) {
    next none if query.blank?

    where(
      "source_mac ILIKE :q OR bssid ILIKE :q OR destination_bssid ILIKE :q OR ssid ILIKE :q OR username ILIKE :q OR registered_username ILIKE :q OR device_fingerprint ILIKE :q OR wps_device_name ILIKE :q OR wps_manufacturer ILIKE :q OR wps_model_name ILIKE :q OR COALESCE(src_ip, '') ILIKE :q OR COALESCE(dst_ip, '') ILIKE :q OR COALESCE(app_protocol, '') ILIKE :q OR COALESCE(hostname, '') ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }
end
