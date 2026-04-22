class AuditWindowPublisher
  SUBJECT = "wireless.audit.config"

  def initialize(audit_window, publisher: Nats::Publisher.new)
    @audit_window = audit_window
    @publisher = publisher
  end

  def call
    @publisher.publish(SUBJECT, @audit_window.payload)
  end
end
