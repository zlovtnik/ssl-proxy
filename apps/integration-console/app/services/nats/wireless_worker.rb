require "json"
require "nats/client"

module Nats
  class WirelessWorker
    # Mapping of consumer names to their stream and subject
    CONSUMER_CONFIG = {
      "wireless-backlog-list" => {
        stream_env: "WIRELESS_BACKLOG_STREAM",
        stream_default: "WIRELESS_BACKLOG_STREAM",
        subject: "wireless.backlog.list",
        replies_to: "wireless.backlog.list.reply",
      },
      "wireless-backlog-save" => {
        stream_env: "WIRELESS_BACKLOG_STREAM",
        stream_default: "WIRELESS_BACKLOG_STREAM",
        subject: "wireless.backlog.save",
      },
      "wireless-backlog-synced" => {
        stream_env: "WIRELESS_BACKLOG_STREAM",
        stream_default: "WIRELESS_BACKLOG_STREAM",
        subject: "wireless.backlog.synced",
      },
      "wireless-backlog-prune" => {
        stream_env: "WIRELESS_BACKLOG_STREAM",
        stream_default: "WIRELESS_BACKLOG_STREAM",
        subject: "wireless.backlog.prune",
        replies_to: "wireless.backlog.prune.reply",
      },
      "wireless-mac-lookup" => {
        stream_env: "WIRELESS_MAC_STREAM",
        stream_default: "WIRELESS_MAC_STREAM",
        subject: "wireless.mac.lookup",
        replies_to: "wireless.mac.lookup.reply",
      },
      "wireless-networks-authorized" => {
        stream_env: "WIRELESS_NETWORKS_STREAM",
        stream_default: "WIRELESS_NETWORKS_STREAM",
        subject: "wireless.networks.authorized",
        replies_to: "wireless.networks.authorized.reply",
      },
      "wireless-probe-flush" => {
        stream_env: "WIRELESS_PROBE_STREAM",
        stream_default: "WIRELESS_PROBE_STREAM",
        subject: "wireless.probe.flush",
      },
    }.freeze

    FETCH_TIMEOUT = 0.5
    POLL_INTERVAL = 0.5
    HEALTH_FILE = "/tmp/wireless-worker-health"

    def self.healthy?
      File.exist?(HEALTH_FILE) && (Time.now - File.mtime(HEALTH_FILE)) < 60
    end

    def touch_health
      File.write(HEALTH_FILE, Time.now.iso8601)
    rescue => e
      nil
    end

    def initialize(url: ENV.fetch("SYNC_NATS_URL", "nats://127.0.0.1:4222"),
                   client: nil,
                   poll_interval: POLL_INTERVAL)
      @url = url
      @client = client
      @poll_interval = poll_interval
      @running = false
      @js = nil
      @pull_subs = {}
    end

    def run_forever
      @running = true
      owns_client = @client.nil?
      @client ||= ::NATS.connect(servers: [@url])
      @js = @client.jetstream

      setup_pull_subscriptions

      Rails.logger.info("[WirelessWorker] Starting wireless worker loop with #{CONSUMER_CONFIG.size} consumers")

      while @running
        begin
          CONSUMER_CONFIG.each_key do |consumer_name|
            break unless @running
            process_consumer(consumer_name)
          end
        rescue => e
          Rails.logger.error("[WirelessWorker] Error in worker loop: #{e.class} #{e.message}")
          Rails.logger.error("[WirelessWorker] #{e.backtrace.first(5).join("\n")}")
        end

        touch_health
        sleep @poll_interval if @running
      end
    ensure
      cleanup_subscriptions
      @client&.close if owns_client && @client.respond_to?(:close)
      @client = nil if owns_client
      Rails.logger.info("[WirelessWorker] Wireless worker loop stopped")
    end

    def stop
      @running = false
    end

    private

    def setup_pull_subscriptions
      CONSUMER_CONFIG.each do |consumer_name, config|
        stream = ENV.fetch(config[:stream_env], config[:stream_default])
        begin
          sub = @js.pull_subscribe(durable: consumer_name, stream: stream)
          @pull_subs[consumer_name] = { sub: sub, config: config }
          Rails.logger.info("[WirelessWorker] Created pull subscription for #{consumer_name} on stream #{stream}")
        rescue => e
          Rails.logger.error("[WirelessWorker] Failed to create pull subscription for #{consumer_name}: #{e.class} #{e.message}")
        end
      end
    end

    def cleanup_subscriptions
      @pull_subs.each_value do |entry|
        entry[:sub]&.unsubscribe rescue nil
      end
      @pull_subs.clear
    end

    def process_consumer(consumer_name)
      entry = @pull_subs[consumer_name]
      return unless entry

      sub = entry[:sub]
      config = entry[:config]

      msgs = sub.fetch(max_msgs: 1, timeout: FETCH_TIMEOUT)
      return if msgs.empty?

      msg = msgs.first
      payload = decode(msg.data)
      handle_message(consumer_name, msg, payload, config)
    rescue ::NATS::JetStream::TimeoutError, ::NATS::TimeoutError
      # No messages available, which is normal
    rescue => e
      Rails.logger.error("[WirelessWorker] Error processing #{consumer_name}: #{e.class} #{e.message}")
    end

    def handle_message(consumer_name, msg, payload, config)
      case consumer_name
      when "wireless-backlog-list"
        handle_backlog_list(msg, payload, config)
      when "wireless-backlog-save"
        handle_backlog_save(msg, payload, config)
      when "wireless-backlog-synced"
        handle_backlog_synced(msg, payload, config)
      when "wireless-backlog-prune"
        handle_backlog_prune(msg, payload, config)
      when "wireless-mac-lookup"
        handle_mac_lookup(msg, payload, config)
      when "wireless-networks-authorized"
        handle_networks_authorized(msg, payload, config)
      when "wireless-probe-flush"
        handle_probe_flush(msg, payload, config)
      else
        Rails.logger.warn("[WirelessWorker] Unknown consumer: #{consumer_name}")
        msg.ack
      end
    rescue => e
      Rails.logger.error("[WirelessWorker] Handler error for #{consumer_name}: #{e.class} #{e.message}")
      msg.nak rescue nil
    end

    def decode(data)
      JSON.parse(data.to_s)
    rescue JSON::ParserError
      { "raw" => data.to_s }
    end

    def reply(msg, payload, config)
      # The Rust sensor embeds its reply inbox in the JSON payload rather than
      # using the NATS protocol-level reply field. Re-parse the original message
      # data to find it, since handlers may build a brand-new response hash.
      original = decode(msg.data) rescue {}
      embedded_reply = original.is_a?(Hash) ? original["reply_subject"] : nil
      reply_subject = embedded_reply || msg.reply || config[:replies_to]
      return unless reply_subject

      body = payload.is_a?(String) ? payload : JSON.generate(payload)
      @client.publish(reply_subject, body)
      @client.flush if @client.respond_to?(:flush)
    rescue => e
      Rails.logger.error("[WirelessWorker] Reply error: #{e.class} #{e.message}")
    end

    # ── Consumer Handlers ──────────────────────────────────────────────────

    def handle_backlog_list(msg, _payload, config)
      entries = BacklogStatus.pending.or(BacklogStatus.failed).order(updated_at: :asc)
      result = entries.map do |entry|
        {
          dedupe_key: entry.dedupe_key,
          stream_name: entry.stream_name,
          payload: begin; JSON.parse(entry.payload); rescue; entry.payload; end,
          status: entry.status,
          attempt_count: entry.attempt_count,
          created_at: entry.created_at&.iso8601,
          updated_at: entry.updated_at&.iso8601,
        }
      end

      reply(msg, result, config)
      msg.ack
    end

    def handle_backlog_save(msg, payload, _config)
      dedupe_key = payload["dedupe_key"] || SecureRandom.uuid
      stream_name = payload["stream_name"]
      payload_data = payload["payload"]

      BacklogStatus.create_with(
        stream_name: stream_name,
        payload: payload_data.to_json,
        status: "pending",
        attempt_count: 0
      ).find_or_create_by!(dedupe_key: dedupe_key)

      msg.ack
    end

    def handle_backlog_synced(msg, payload, _config)
      dedupe_key = payload["dedupe_key"]
      if dedupe_key
        BacklogStatus.where(dedupe_key: dedupe_key)
          .update_all(status: "synced", updated_at: Time.current)
      end
      msg.ack
    end

    def handle_backlog_prune(msg, payload, config)
      max_age_hours = payload.fetch("max_age_hours", 72)
      cutoff = Time.current - max_age_hours.hours

      pruned = BacklogStatus.where(status: "synced")
        .where("updated_at < ?", cutoff)
        .delete_all

      reply(msg, { "pruned" => pruned }, config)
      msg.ack
    end

    def handle_mac_lookup(msg, payload, config)
      mac = (payload["mac"] || payload["mac_address"]).to_s.strip.downcase
      if mac.blank?
        reply(msg, { "error" => "mac required" }, config)
        msg.ack
        return
      end

      device = Device.find_by(mac_id: mac) || Device.find_by(mac_hint: mac)

      if device
        reply(msg, {
          "device_id" => device.device_id,
          "username" => device.username,
          "display_name" => device.display_name,
          "hostname" => device.hostname,
          "os_hint" => device.os_hint,
        }, config)
      else
        reply(msg, { "device_id" => nil, "username" => nil }, config)
      end

      msg.ack
    end

    def handle_networks_authorized(msg, _payload, config)
      networks = AuthorizedWirelessNetwork.enabled.ordered.map do |net|
        {
          id: net.id,
          ssid: net.ssid,
          bssid: net.bssid,
          location_id: net.location_id,
          enabled: net.enabled,
        }
      end

      reply(msg, { "networks" => networks }, config)
      msg.ack
    end

    def handle_probe_flush(msg, payload, _config)
      observations = payload["observations"]
      observations = [observations] unless observations.is_a?(Array)

      count = 0
      observations.each do |obs|
        next if obs["mac_address"].blank?
        WirelessProbeObservation.upsert_observation(obs)
        count += 1
      end

      Rails.logger.info("[WirelessWorker] Upserted #{count} probe observations")
      msg.ack
    end
  end
end