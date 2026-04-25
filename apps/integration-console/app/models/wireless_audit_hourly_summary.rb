class WirelessAuditHourlySummary < SyncRecord
  self.table_name = "mv_wireless_audit_hourly_summary"
  self.primary_key = nil

  scope :recent, -> { where(hour: 24.hours.ago..) }
end
