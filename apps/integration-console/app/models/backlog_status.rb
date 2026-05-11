class BacklogStatus < SyncRecord
  self.table_name = "audit_backlog"
  self.primary_key = "dedupe_key"

  scope :pending, -> { where(status: "pending") }
  scope :failed, -> { where(status: "sync_failed").or(where(status: "failed")) }
  scope :ordered_by_updated, -> { order(updated_at: :asc) }

  def self.pending_count = pending.count
  def self.failed_count = failed.count

  def self.status_counts
    counts = select(
      "COUNT(*) FILTER (WHERE status = 'pending') AS pending_count",
      "COUNT(*) FILTER (WHERE status IN ('sync_failed','failed')) AS failed_count"
    ).take

    {
      pending_count: counts.pending_count.to_i,
      failed_count: counts.failed_count.to_i
    }
  end
end
