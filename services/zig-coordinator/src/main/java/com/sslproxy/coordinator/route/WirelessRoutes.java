package com.sslproxy.coordinator.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.CheckedConsumer;
import com.sslproxy.coordinator.fp.WirelessHandler;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.regex.Pattern;

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
    private static final Pattern KAFKA_TOPIC_PATTERN = Pattern.compile("[A-Za-z0-9._-]{1,249}");

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
                .maximumRedeliveries("{{coordinator.wireless-route-max-retries:3}}")
                .redeliveryDelay(500)
                .useOriginalMessage()
                .handled(true)
                .process(this::logRouteFailure)
                .toD("kafka:${exchangeProperty.dlqTopic}");

        from(wirelessConsumerUri(props.wirelessBacklogSaveTopic(), props.wirelessBacklogSaveConsumer()))
        .routeId("wireless-backlog-save")
        .setProperty("dlqTopic", constant(props.wirelessBacklogSaveTopic() + ".dlq"))
        .process(voidHandler(payload -> {
            db.saveBacklogEntry(payload).orElseThrow();
            log.info("event=backlog_save status=ok payload_bytes={}", payload.length());
        }));

        from(wirelessConsumerUri(props.wirelessBacklogListTopic(), props.wirelessBacklogListConsumer()))
        .routeId("wireless-backlog-list")
        .setProperty("dlqTopic", constant(props.wirelessBacklogListTopic() + ".dlq"))
        .process(replyingHandler(
                payload -> db.listPendingBacklog().orElse("[]"),
                props.wirelessBacklogListReplyTopic(),
                "backlog_list"
        ));

        from(wirelessConsumerUri(props.wirelessBacklogSyncedTopic(), props.wirelessBacklogSyncedConsumer()))
        .routeId("wireless-backlog-synced")
        .setProperty("dlqTopic", constant(props.wirelessBacklogSyncedTopic() + ".dlq"))
        .process(voidHandler(payload -> {
            String dedupeKey = extractField(payload, "dedupe_key");
            if (dedupeKey == null || dedupeKey.isEmpty()) {
                log.warn("event=backlog_synced status=missing_dedupe_key");
                return;
            }
            db.markBacklogSynced(dedupeKey).orElseThrow();
            log.info("event=backlog_synced status=ok dedupe_key={}", dedupeKey);
        }));

        from(wirelessConsumerUri(props.wirelessBacklogPruneTopic(), props.wirelessBacklogPruneConsumer()))
        .routeId("wireless-backlog-prune")
        .setProperty("dlqTopic", constant(props.wirelessBacklogPruneTopic() + ".dlq"))
        .process(replyingHandler(
                payload -> String.format("{\"pruned\":%d}", parseLongOrZero(db.pruneBacklog().orElse("0"))),
                props.wirelessBacklogPruneReplyTopic(),
                "backlog_prune"
        ));

        from(wirelessConsumerUri(props.wirelessMacLookupTopic(), props.wirelessMacLookupConsumer()))
        .routeId("wireless-mac-lookup")
        .setProperty("dlqTopic", constant(props.wirelessMacLookupTopic() + ".dlq"))
        .process(replyingHandler(
                payload -> {
                    String mac = extractField(payload, "mac");
                    if (mac == null || mac.isEmpty()) {
                        log.warn("event=mac_lookup status=missing_mac");
                        return null;
                    }
                    return db.lookupDeviceByMac(mac).orElse("null");
                },
                props.wirelessMacLookupReplyTopic(),
                "mac_lookup"
        ));

        from(wirelessConsumerUri(props.wirelessNetworksAuthorizedTopic(), props.wirelessNetworksAuthorizedConsumer()))
        .routeId("wireless-networks-authorized")
        .setProperty("dlqTopic", constant(props.wirelessNetworksAuthorizedTopic() + ".dlq"))
        .process(replyingHandler(
                payload -> db.listAuthorizedNetworks().orElse("[]"),
                props.wirelessNetworksAuthorizedReplyTopic(),
                "networks_authorized"
        ));

        from(wirelessConsumerUri(props.wirelessProbeFlushTopic(), props.wirelessProbeFlushConsumer()))
        .routeId("wireless-probe-flush")
        .setProperty("dlqTopic", constant(props.wirelessProbeFlushTopic() + ".dlq"))
        .process(voidHandler(payload -> {
            db.flushProbeBatch(payload).orElseThrow();
            log.info("event=probe_flush status=ok payload_bytes={}", payload.length());
        }));
    }

    Processor replyingHandler(WirelessHandler handler,
                              String defaultReplyTopic,
                              String eventName) {
        return exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) {
                return;
            }

            String replyTopic = resolveReplyTopic(payload, defaultReplyTopic);
            try {
                String reply = handler.handle(payload);
                if (reply == null) {
                    return;
                }
                producerTemplate.sendBody("kafka:" + replyTopic, reply);
                log.info("event={} status=ok reply_topic={} payload_bytes={}",
                        eventName, replyTopic, reply.length());
            } catch (Exception e) {
                log.error("event={} status=failed reply_topic={} error={}",
                        eventName, replyTopic, sanitize(e.getMessage()));
                throw e;
            }
        };
    }

    Processor voidHandler(CheckedConsumer<String> handler) {
        return exchange -> {
            String payload = exchange.getIn().getBody(String.class);
            if (payload == null || payload.isEmpty()) {
                return;
            }
            try {
                handler.accept(payload);
            } catch (Exception e) {
                log.error("event=wireless_void_handler_failed error={}", sanitize(e.getMessage()));
                throw e;
            }
        };
    }

    /**
     * Resolves the reply topic from a JSON payload containing an optional
     * {@code reply_topic} field. Falls back to the configured default topic.
     */
    String resolveReplyTopic(String payload, String defaultTopic) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(payload, Map.class);
            Object topic = parsed.get("reply_topic");
            if (topic instanceof String topicName && !topicName.isBlank()) {
                String trimmedTopic = topicName.trim();
                if (isValidKafkaTopic(trimmedTopic) && isAllowedReplyTopic(trimmedTopic, defaultTopic)) {
                    return trimmedTopic;
                }
                log.warn("event=resolve_reply_topic status=invalid_reply_topic");
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

    private String wirelessConsumerUri(String topic, String consumerGroup) {
        return "kafka:" + topic
                + "?groupId=" + consumerGroup
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords=" + props.wirelessMaxPollRecords()
                + "&consumersCount=" + props.wirelessConsumersCount()
                + "&breakOnFirstError=true";
    }

    private void logRouteFailure(Exchange exchange) {
        Exception error = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
        String dlqTopic = exchange.getProperty("dlqTopic", String.class);
        log.atError()
                .addKeyValue("event", "wireless_operation")
                .addKeyValue("status", "dlq")
                .addKeyValue("dlq_topic", dlqTopic == null ? "" : dlqTopic)
                .addKeyValue("error", sanitize(error == null ? "" : error.getMessage()))
                .log("wireless operation routed to DLQ");
    }

    private boolean isValidKafkaTopic(String topic) {
        return KAFKA_TOPIC_PATTERN.matcher(topic).matches()
                && !".".equals(topic)
                && !"..".equals(topic);
    }

    private boolean isAllowedReplyTopic(String topic, String defaultTopic) {
        return topic.equals(defaultTopic)
                || topic.equals(props.wirelessBacklogListReplyTopic())
                || topic.equals(props.wirelessBacklogPruneReplyTopic())
                || topic.equals(props.wirelessMacLookupReplyTopic())
                || topic.equals(props.wirelessNetworksAuthorizedReplyTopic())
                || isSensorInboxReplyTopic(topic);
    }

    private boolean isSensorInboxReplyTopic(String topic) {
        String prefix = "_INBOX.atheros_sensor.";
        return topic.startsWith(prefix) && topic.length() > prefix.length();
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
