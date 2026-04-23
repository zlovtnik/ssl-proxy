class ShadowItAlert < SyncRecord
  self.table_name = "v_shadow_it_alerts"
  self.primary_key = "alert_id"

  scope :recent, -> { order(observed_at: :desc) }
  scope :open, -> { where(resolved_at: nil) }
  scope :search, ->(query) {
    next none if query.blank?

    where(
      "source_mac ILIKE :q OR destination_bssid ILIKE :q OR ssid ILIKE :q OR sensor_id ILIKE :q OR location_id ILIKE :q OR reason ILIKE :q",
      q: "%#{sanitize_sql_like(query)}%"
    )
  }

  def evidence_value(key)
    evidence.is_a?(Hash) ? evidence[key.to_s] : nil
  end
end
