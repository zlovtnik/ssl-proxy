class WirelessAuditIdentity < SyncRecord
  self.table_name = "v_wireless_audit_with_devices"
  self.primary_key = "dedupe_key"

  scope :recent, -> { order(observed_at: :desc) }
  scope :search, ->(query) {
    next none if query.blank?

    where(
      "source_mac ILIKE :q OR bssid ILIKE :q OR ssid ILIKE :q OR username ILIKE :q OR registered_username ILIKE :q OR device_fingerprint ILIKE :q OR wps_device_name ILIKE :q OR wps_manufacturer ILIKE :q OR wps_model_name ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }
end
