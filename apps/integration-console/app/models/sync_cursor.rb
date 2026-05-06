class SyncCursor < SyncRecord
  self.table_name = "sync_cursor"
  self.primary_key = "stream_name"
end
