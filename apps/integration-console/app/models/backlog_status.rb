class BacklogStatus < SyncRecord
  self.table_name = "audit_backlog"
  self.primary_key = "dedupe_key"

  scope :pending, -> { where(status: "pending") }
  scope :failed, -> { where(status: "sync_failed").or(where(status: "failed")) }

  def self.pending_count = pending.count
  def self.failed_count = failed.count
end
