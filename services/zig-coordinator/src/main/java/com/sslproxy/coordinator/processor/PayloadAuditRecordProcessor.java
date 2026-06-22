package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.BoundedAccumulator;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import com.sslproxy.coordinator.util.Sha256Utils;
import io.vavr.control.Try;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.List;

/**
 * Translates direct proxy.payload_audit messages into the coordinator's
 * scan-request ledger so payload audit uses the same idempotent dispatch path.
 */
@Component
public class PayloadAuditRecordProcessor implements Processor {

    static final String STREAM_NAME = "proxy.payload_audit";

    private static final Logger log = LoggerFactory.getLogger(PayloadAuditRecordProcessor.class);

    private final ObjectMapper objectMapper;
    private final DatabaseService databaseService;
    private final CoordinatorProperties props;
    private final BoundedAccumulator<DatabaseService.ScanRequestRecord> accumulator;

    public PayloadAuditRecordProcessor(ObjectMapper objectMapper,
                                       DatabaseService databaseService,
                                       CoordinatorProperties props) {
        this.objectMapper = objectMapper;
        this.databaseService = databaseService;
        this.props = props;
        this.accumulator = new BoundedAccumulator<>("payload-audit", maxPendingResults(props));
    }

    @Override
    public void process(Exchange exchange) {
        String rawJson = exchange.getIn().getBody(String.class);
        if (rawJson == null || rawJson.isEmpty()) {
            return;
        }

        buildRecord(rawJson)
                .onSuccess(record -> {
                    if (!accumulator.offer(record)) {
                        log.atError()
                                .addKeyValue("event", "payload_audit_ingest")
                                .addKeyValue("status", "rejected")
                                .addKeyValue("reason", "accumulator_full")
                                .addKeyValue("pending_count", accumulator.size())
                                .addKeyValue("max_pending", accumulator.capacity())
                                .log("payload audit accumulator rejected record");
                        throw new IllegalStateException("Pending payload audit accumulator is full");
                    }
                    flushPendingOrThrow();
                })
                .onFailure(error -> log.atError()
                        .addKeyValue("event", "payload_audit_invalid")
                        .addKeyValue("error", sanitize(error.getMessage()))
                        .addKeyValue("payload_bytes", rawJson.getBytes(StandardCharsets.UTF_8).length)
                        .log("payload audit record rejected"));
    }

    public void flushPending() {
        flushPending(false);
    }

    private Try<DatabaseService.ScanRequestRecord> buildRecord(String rawJson) {
        return Try.of(() -> {
            JsonNode payload = objectMapper.readTree(rawJson);
            if (payload == null || !payload.isObject()) {
                throw new IllegalArgumentException("payload audit message must be a JSON object");
            }
            String observedAt = observedAt(payload);
            byte[] payloadBytes = rawJson.getBytes(StandardCharsets.UTF_8);
            String payloadSha256 = Sha256Utils.sha256Hex(payloadBytes);
            String dedupeKey = Sha256Utils.sha256Hex(STREAM_NAME + ":" + payloadSha256);

            ObjectNode request = objectMapper.createObjectNode();
            request.put("stream_name", STREAM_NAME);
            request.put("dedupe_key", dedupeKey);
            request.put("payload_ref", inlinePayloadRef(payloadBytes));
            request.put("observed_at", observedAt);

            return new DatabaseService.ScanRequestRecord(
                    objectMapper.writeValueAsString(request),
                    rawJson,
                    payloadSha256
            );
        });
    }

    private String observedAt(JsonNode payload) {
        JsonNode observedAt = payload.get("observed_at");
        if (observedAt == null || !observedAt.isTextual() || observedAt.asText().isBlank()) {
            throw new IllegalArgumentException("payload audit missing observed_at");
        }
        String value = observedAt.asText();
        try {
            OffsetDateTime.parse(value);
            return value;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("payload audit observed_at must be RFC3339 timestamp");
        }
    }

    private String inlinePayloadRef(byte[] payloadBytes) {
        return "inline://json/" + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(payloadBytes);
    }

    private void flushPendingOrThrow() {
        flushPending(true);
    }

    private void flushPending(boolean failOnError) {
        List<DatabaseService.ScanRequestRecord> batch = accumulator.drain(props.scanFetchCount());
        if (batch.isEmpty()) {
            return;
        }

        switch (databaseService.recordScanRequests(batch)) {
            case DbResult.Ok<Integer> ok -> log.atInfo()
                    .addKeyValue("event", "payload_audit_ingest")
                    .addKeyValue("status", "recorded")
                    .addKeyValue("count", ok.value())
                    .addKeyValue("batch_size", batch.size())
                    .log("payload audit batch recorded");
            case DbResult.Empty<Integer> ignored -> log.atInfo()
                    .addKeyValue("event", "payload_audit_ingest")
                    .addKeyValue("status", "recorded")
                    .addKeyValue("count", 0)
                    .addKeyValue("batch_size", batch.size())
                    .log("payload audit batch recorded");
            case DbResult.Err<Integer> err -> {
                log.atError()
                        .addKeyValue("event", "payload_audit_ingest")
                        .addKeyValue("status", "failed")
                        .addKeyValue("operation", err.operation())
                        .addKeyValue("batch_size", batch.size())
                        .addKeyValue("error", sanitize(err.cause().getMessage()))
                        .log("payload audit batch failed");
                int dropped = accumulator.requeueFront(batch);
                if (dropped > 0) {
                    log.atError()
                            .addKeyValue("event", "payload_audit_ingest")
                            .addKeyValue("status", "dropped")
                            .addKeyValue("reason", "accumulator_full")
                            .addKeyValue("dropped_count", dropped)
                            .addKeyValue("pending_count", accumulator.size())
                            .addKeyValue("max_pending", accumulator.capacity())
                            .log("payload audit retry records dropped");
                }
                if (failOnError) {
                    throw new IllegalStateException(err.operation(), err.cause());
                }
            }
        }
    }

    private static int maxPendingResults(CoordinatorProperties props) {
        int multiplier = Math.max(1, props.backpressureBudgetMultiplier());
        return Math.max(1, props.scanFetchCount()) * multiplier;
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
