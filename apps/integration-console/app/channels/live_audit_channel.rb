class LiveAuditChannel < ApplicationCable::Channel
  def subscribed
    stream_from "live_audit"
  end
end
