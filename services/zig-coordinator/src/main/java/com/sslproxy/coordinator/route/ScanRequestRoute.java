package com.sslproxy.coordinator.route;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.processor.ScanRecordProcessor;
import org.apache.camel.Exchange;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Consumes scan requests from sync.scan.request via Kafka consumer group.
 * Directly replaces sync_handlers.zig drainScanRequests() and CLI-based
 * service_redpanda.zig pullScanBatch().
 *
 * With Camel Kafka, the consumer group handles offset management automatically,
 * replacing the manual cursor logic in the Zig version.
 *
 * Each message is processed by ScanRecordProcessor which:
 * - Deserializes the ScanRequest JSON
 * - Resolves the payload_ref (inline://json/ or outbox://)
 * - Computes SHA-256 of the payload
 * - Accumulates into batches and flushes to DB via record_scan_request_batch()
 */
@Component
public class ScanRequestRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(ScanRequestRoute.class);

    private final CoordinatorProperties props;
    private final ScanRecordProcessor scanRecordProcessor;

    public ScanRequestRoute(CoordinatorProperties props,
                            ScanRecordProcessor scanRecordProcessor) {
        this.props = props;
        this.scanRecordProcessor = scanRecordProcessor;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .maximumRedeliveries("{{coordinator.scan-route-max-retries:3}}")
                .redeliveryDelay(500)
                .useOriginalMessage()
                .handled(true)
                .process(exchange -> logRouteFailure(exchange, props.scanTopic() + ".dlq"))
                .to("kafka:{{coordinator.scan-topic}}.dlq");

        // Consume from sync.scan.request with the zig-coordinator-scan consumer group
        from("kafka:{{coordinator.scan-topic}}"
                + "?groupId={{coordinator.scan-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.scan-fetch-count}}"
                + "&consumersCount={{coordinator.scan-consumers-count}}"
                + "&breakOnFirstError=true")
        .routeId("scan-request-consumer")
        .process(exchange -> {
            String body = exchange.getIn().getBody(String.class);
            int payloadBytes = body == null ? 0 : body.getBytes(StandardCharsets.UTF_8).length;
            log.atTrace()
                    .addKeyValue("event", "scan_request_ingest")
                    .addKeyValue("status", "received")
                    .addKeyValue("route", "scan-request-consumer")
                    .addKeyValue("topic", props.scanTopic())
                    .addKeyValue("consumer_group", props.scanConsumer())
                    .addKeyValue("payload_bytes", payloadBytes)
                    .log("scan request received");
        })
        .process(scanRecordProcessor);

        // Timer-based flush for partial batches — ensures records don't sit in the
        // accumulator indefinitely when Kafka delivers fewer messages than the batch size
        from("timer:scan-flush?period=1000&daemon=true")
                .routeId("scan-request-flush-timer")
                .bean(scanRecordProcessor, "flushPending")
                .log(LoggingLevel.TRACE, "event=scan_request_flush_timer status=tick");
    }

    private void logRouteFailure(Exchange exchange, String dlqTopic) {
        Exception error = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
        log.atError()
                .addKeyValue("event", "scan_request_ingest")
                .addKeyValue("status", "dlq")
                .addKeyValue("dlq_topic", dlqTopic)
                .addKeyValue("error", sanitize(error == null ? "" : error.getMessage()))
                .log("scan request routed to DLQ");
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
