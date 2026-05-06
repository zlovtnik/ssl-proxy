class SyncJob < SyncRecord
  self.table_name = "sync_job"
  self.primary_key = "job_id"

  has_many :sync_batches, foreign_key: :job_id, primary_key: :job_id
end
