class SyncError < SyncRecord
  self.table_name = "sync_error"

  belongs_to :sync_batch, foreign_key: :batch_id, primary_key: :batch_id, optional: true
  belongs_to :sync_job, foreign_key: :job_id, primary_key: :job_id, optional: true
end
