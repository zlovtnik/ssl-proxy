require "json"
require "nats/client"

module Nats
  class Publisher
    def initialize(url: ENV.fetch("SYNC_NATS_URL", "nats://127.0.0.1:4222"), client: nil)
      @url = url
      @client = client
    end

    def publish(subject, payload)
      body = payload.is_a?(String) ? payload : JSON.generate(payload)
      with_client do |client|
        client.publish(subject, body)
        client.flush if client.respond_to?(:flush)
      end
      subject
    end

    private

    def with_client
      return yield @client if @client

      client = NATS.connect(servers: [@url])
      yield client
    ensure
      client&.close unless @client
    end
  end
end
