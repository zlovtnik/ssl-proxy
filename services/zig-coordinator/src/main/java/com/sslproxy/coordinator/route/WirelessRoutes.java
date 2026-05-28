package com.sslproxy.coordinator.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.LoggingLevel;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * Wireless operation routes that handle the 7 wireless handlers from
 * wireless_handlers.zig:
 *   1. backlog save
 *   2. backlog list
 *   3. backlog synced
 *   4. backlog prune
 *   5. MAC lookup
 *   6. networks authorized
 *   7. probe flush
 *
 * Each wireless handler has its own Kafka consumer group for independent
 * consumption, replacing the Zig pattern of pulling one message at a time.
 *
 * Handlers 2, 4, 5, 6 follow a request/reply pattern: they parse an optional
 * reply_topic from the incoming message, run the DB operation, and publish
 * the result to the reply topic (or the configured default).
 */
@Component
public class WirelessRoutes extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(WirelessRoutes.class);

    private final CoordinatorProperties props;
    private final DatabaseService db;
    private final ObjectMapper objectMapper;

    public WirelessRoutes(CoordinatorProperties props,
                          DatabaseService db,
                          ObjectMapper objectMapper) {
        this.props = props;
        this.db = db;
        this.objectMapper = objectMapper;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .log(LoggingLevel.ERROR, "event=wireless_operation status=error error=${exception.message}")
                .continued(true);

        // =====================================================================
        // 1. Backlog Save consumer (fire-and-forget)
        //    Saves a raw backlog entry JSON to the DB.
        // =====================================================================
        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-save-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-backlog-save")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;
            db.saveBacklogEntry(payload);
            log.info("event=backlog_save status=ok payload_bytes={}", payload.length());
        });

        // =====================================================================
        // 2. Backlog List consumer (request/reply pattern)
        //    Parses optional reply_topic from the request, fetches the pending
        //    backlog list from DB, and publishes the result to the reply topic.
        // =====================================================================
        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-list-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-backlog-list")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;

            String replyTopic = resolveReplyTopic(payload, props.getWirelessBacklogListReplyTopic());
            Optional<String> list = db.listPendingBacklog();
            String result = list.orElse("[]");

            ProducerTemplate producer = exchange.getContext().createProducerTemplate();
            producer.sendBody("kafka:" + replyTopic, result);

            log.info("event=backlog_list status=ok reply_topic={} payload_bytes={}",
                    replyTopic, result.length());
        });

        // =====================================================================
        // 3. Backlog Synced consumer (fire-and-forget)
        //    Parses dedupe_key from the request and marks the backlog entry
        //    as synced in the DB.
        // =====================================================================
        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-synced-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-backlog-synced")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;

            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(payload, Map.class);
            String dedupeKey = (String) parsed.get("dedupe_key");
            if (dedupeKey == null || dedupeKey.isEmpty()) {
                log.warn("event=backlog_synced status=missing_dedupe_key");
                return;
            }

            db.markBacklogSynced(dedupeKey);
            log.info("event=backlog_synced status=ok dedupe_key={}", dedupeKey);
        });

        // =====================================================================
        // 4. Backlog Prune consumer (request/reply pattern)
        //    Parses optional reply_topic, prunes synced backlog entries from DB,
        //    and publishes {"pruned": N} to the reply topic.
        // =====================================================================
        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-prune-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-backlog-prune")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;

            String replyTopic = resolveReplyTopic(payload, props.getWirelessBacklogPruneReplyTopic());
            Optional<String> deleted = db.pruneBacklog();
            long count = deleted.map(Long::parseLong).orElse(0L);
            String reply = String.format("{\"pruned\":%d}", count);

            ProducerTemplate producer = exchange.getContext().createProducerTemplate();
            producer.sendBody("kafka:" + replyTopic, reply);

            log.info("event=backlog_prune status=ok reply_topic={} deleted_count={}",
                    replyTopic, count);
        });

        // =====================================================================
        // 5. MAC Lookup consumer (request/reply pattern)
        //    Parses mac + optional reply_topic, looks up the device by MAC,
        //    and publishes the device JSON (or null) to the reply topic.
        // =====================================================================
        from("kafka:{{coordinator.wireless-mac-stream-name}}"
                + "?groupId={{coordinator.wireless-mac-lookup-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-mac-lookup")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;

            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(payload, Map.class);
            String mac = (String) parsed.get("mac");
            if (mac == null || mac.isEmpty()) {
                log.warn("event=mac_lookup status=missing_mac");
                return;
            }

            String replyTopic = resolveReplyTopic(payload, props.getWirelessMacLookupReplyTopic());
            Optional<String> device = db.lookupDeviceByMac(mac);
            String result = device.orElse("null");

            ProducerTemplate producer = exchange.getContext().createProducerTemplate();
            producer.sendBody("kafka:" + replyTopic, result);

            log.info("event=mac_lookup status=ok mac={} reply_topic={} found={}",
                    mac, replyTopic, device.isPresent());
        });

        // =====================================================================
        // 6. Networks Authorized consumer (request/reply pattern)
        //    Parses optional reply_topic, fetches the authorized networks list
        //    from DB, and publishes the result to the reply topic.
        // =====================================================================
        from("kafka:{{coordinator.wireless-networks-stream-name}}"
                + "?groupId={{coordinator.wireless-networks-authorized-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-networks-authorized")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;

            String replyTopic = resolveReplyTopic(payload, props.getWirelessNetworksAuthorizedReplyTopic());
            Optional<String> networks = db.listAuthorizedNetworks();
            String result = networks.orElse("[]");

            ProducerTemplate producer = exchange.getContext().createProducerTemplate();
            producer.sendBody("kafka:" + replyTopic, result);

            log.info("event=networks_authorized status=ok reply_topic={} payload_bytes={}",
                    replyTopic, result.length());
        });

        // =====================================================================
        // 7. Probe Flush consumer (fire-and-forget)
        //    Flushes a batch of probe data to the DB.
        // =====================================================================
        from("kafka:{{coordinator.wireless-probe-stream-name}}"
                + "?groupId={{coordinator.wireless-probe-flush-consumer}}"
                + "&autoOffsetReset=earliest&maxPollRecords=1&consumersCount=1")
        .routeId("wireless-probe-flush")
        .process(exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) return;
            db.flushProbeBatch(payload);
            log.info("event=probe_flush status=ok payload_bytes={}", payload.length());
        });
    }

    /**
     * Resolves the reply topic from a JSON payload containing an optional
     * {@code reply_topic} field. Falls back to the configured default topic.
     */
    private String resolveReplyTopic(String payload, String defaultTopic) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(payload, Map.class);
            Object topic = parsed.get("reply_topic");
            if (topic instanceof String && !((String) topic).isEmpty()) {
                return (String) topic;
            }
        } catch (Exception e) {
            log.trace("event=resolve_reply_topic status=parse_error message={}", e.getMessage());
        }
        return defaultTopic;
    }
}
