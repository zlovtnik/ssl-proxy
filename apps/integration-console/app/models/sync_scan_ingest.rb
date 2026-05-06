class SyncScanIngest < SyncRecord
  self.table_name = "sync_scan_ingest"
  self.primary_key = "dedupe_key"
end
