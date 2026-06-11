package com.sslproxy.coordinator.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.CheckedConsumer;
import com.sslproxy.coordinator.fp.WirelessHandler;
import com.sslproxy.coordinator.service.DatabaseService;
import io.vavr.control.Try;
import org.apache.camel.LoggingLevel;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

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
    private final ProducerTemplate producerTemplate;

    public WirelessRoutes(CoordinatorProperties props,
                          DatabaseService db,
                          ObjectMapper objectMapper,
                          ProducerTemplate producerTemplate) {
        this.props = props;
        this.db = db;
        this.objectMapper = objectMapper;
        this.producerTemplate = producerTemplate;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .log(LoggingLevel.ERROR, "event=wireless_operation status=error error=${exception.message}")
                .continued(true);

        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-save-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-backlog-save")
        .process(voidHandler(payload -> {
            db.saveBacklogEntry(payload).orElseThrow();
            log.info("event=backlog_save status=ok payload_bytes={}", payload.length());
        }));

        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-list-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-backlog-list")
        .process(replyingHandler(
                payload -> db.listPendingBacklog().orElse("[]"),
                props.getWirelessBacklogListReplyTopic(),
                "backlog_list"
        ));

        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-synced-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-backlog-synced")
        .process(voidHandler(payload -> {
            String dedupeKey = extractField(payload, "dedupe_key");
            if (dedupeKey == null || dedupeKey.isEmpty()) {
                log.warn("event=backlog_synced status=missing_dedupe_key");
                return;
            }
            db.markBacklogSynced(dedupeKey).orElseThrow();
            log.info("event=backlog_synced status=ok dedupe_key={}", dedupeKey);
        }));

        from("kafka:{{coordinator.wireless-backlog-stream-name}}"
                + "?groupId={{coordinator.wireless-backlog-prune-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-backlog-prune")
        .process(replyingHandler(
                payload -> String.format("{\"pruned\":%d}", parseLongOrZero(db.pruneBacklog().orElse("0"))),
                props.getWirelessBacklogPruneReplyTopic(),
                "backlog_prune"
        ));

        from("kafka:{{coordinator.wireless-mac-stream-name}}"
                + "?groupId={{coordinator.wireless-mac-lookup-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-mac-lookup")
        .process(replyingHandler(
                payload -> {
                    String mac = extractField(payload, "mac");
                    if (mac == null || mac.isEmpty()) {
                        log.warn("event=mac_lookup status=missing_mac");
                        return null;
                    }
                    return db.lookupDeviceByMac(mac).orElse("null");
                },
                props.getWirelessMacLookupReplyTopic(),
                "mac_lookup"
        ));

        from("kafka:{{coordinator.wireless-networks-stream-name}}"
                + "?groupId={{coordinator.wireless-networks-authorized-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-networks-authorized")
        .process(replyingHandler(
                payload -> db.listAuthorizedNetworks().orElse("[]"),
                props.getWirelessNetworksAuthorizedReplyTopic(),
                "networks_authorized"
        ));

        from("kafka:{{coordinator.wireless-probe-stream-name}}"
                + "?groupId={{coordinator.wireless-probe-flush-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.wireless-max-poll-records}}"
                + "&consumersCount={{coordinator.wireless-consumers-count}}")
        .routeId("wireless-probe-flush")
        .process(voidHandler(payload -> {
            db.flushProbeBatch(payload).orElseThrow();
            log.info("event=probe_flush status=ok payload_bytes={}", payload.length());
        }));
    }

    private Processor replyingHandler(WirelessHandler handler,
                                      String defaultReplyTopic,
                                      String eventName) {
        return exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) {
                return;
            }

            String replyTopic = resolveReplyTopic(payload, defaultReplyTopic);
            Try.of(() -> handler.handle(payload))
                    .onSuccess(reply -> {
                        if (reply == null) {
                            return;
                        }
                        producerTemplate.sendBody("kafka:" + replyTopic, reply);
                        log.info("event={} status=ok reply_topic={} payload_bytes={}",
                                eventName, replyTopic, reply.length());
                    })
                    .onFailure(e -> log.error("event={} status=failed reply_topic={} error={}",
                            eventName, replyTopic, sanitize(e.getMessage())));
        };
    }

    private Processor voidHandler(CheckedConsumer<String> handler) {
        return exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) {
                return;
            }
            Try.run(() -> handler.accept(payload))
                    .onFailure(e -> log.error("event=wireless_void_handler_failed error={}", sanitize(e.getMessage())));
        };
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

    private String extractField(String payload, String fieldName) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = objectMapper.readValue(payload, Map.class);
        Object value = parsed.get(fieldName);
        return value instanceof String stringValue ? stringValue : null;
    }

    private long parseLongOrZero(String value) {
        if (value == null || value.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
