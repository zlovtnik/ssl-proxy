class SyncBatchPayload
  def self.call(batch)
    new(batch).call
  end

  def initialize(batch)
    @batch = batch
  end

  def call
    {
      id: @batch.batch_id,
      batch_no: @batch.batch_no,
      status: @batch.status,
      from_value: @batch.cursor_start,
      to_value: @batch.cursor_end,
      rows_read: @batch.row_count.to_i,
      rows_written: @batch.status == "completed" ? @batch.row_count.to_i : 0,
      rows_errored: @batch.sync_errors.size,
      duration_ms: nil,
      error_detail: @batch.last_error.presence || @batch.sync_errors.map(&:error_text).join("\n").presence,
      created_at: @batch.created_at,
      updated_at: @batch.updated_at
    }
  end
end
