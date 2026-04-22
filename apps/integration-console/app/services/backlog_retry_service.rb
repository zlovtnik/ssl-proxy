BacklogRetryResult = Struct.new(:dedupe_key, :subject, keyword_init: true)

class BacklogRetryService
  def initialize(dedupe_key, publisher: Nats::Publisher.new)
    @dedupe_key = dedupe_key
    @publisher = publisher
  end

  def call
    entry = BacklogStatus.find(@dedupe_key)
    @publisher.publish(entry.stream_name, entry.payload)
    BacklogRetryResult.new(dedupe_key: entry.dedupe_key, subject: entry.stream_name)
  end
end
