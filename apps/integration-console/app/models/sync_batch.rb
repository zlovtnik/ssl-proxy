class SyncBatch < SyncRecord
  self.table_name = "sync_batch"
  self.primary_key = "batch_id"

  belongs_to :sync_job, foreign_key: :job_id, primary_key: :job_id, optional: true
  has_many :sync_errors, foreign_key: :batch_id, primary_key: :batch_id

  def rows_net
    [row_count.to_i - failed_error_count.to_i, 0].max
  end

  def failed_error_count
    status == "failed" ? 1 : 0
  end
end
