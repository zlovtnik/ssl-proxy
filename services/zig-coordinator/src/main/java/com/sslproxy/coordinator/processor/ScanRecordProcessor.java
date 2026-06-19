package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.BoundedAccumulator;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.model.ScanRequest;
import com.sslproxy.coordinator.service.DatabaseService;
import com.sslproxy.coordinator.util.Sha256Utils;
import io.vavr.Tuple;
import io.vavr.Tuple2;
import io.vavr.control.Try;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;

/**
 * Processes scan requests from sync.scan.request Kafka topic.
 *
 * For each message:
 * 1. Deserializes ScanRequest JSON
 * 2. Resolves payload_ref via PayloadResolver (inline://json/ or outbox://)
 * 3. Computes SHA-256 of resolved payload
 * 4. Accumulates into batches of ScanRequestRecord
 * 5. Flushes to DB via DatabaseService.recordScanRequests()
 *
 * Replaces sync_handlers.zig drainScanRequests() logic.
 */
@Component
public class ScanRecordProcessor implements Processor {

    private static final Logger log = LoggerFactory.getLogger(ScanRecordProcessor.class);

    private final ObjectMapper objectMapper;
    private final PayloadResolver payloadResolver;
    private final DatabaseService databaseService;
    private final CoordinatorProperties props;
    private final BoundedAccumulator<DatabaseService.ScanRequestRecord> accumulator;

    public ScanRecordProcessor(ObjectMapper objectMapper,
                               PayloadResolver payloadResolver,
                               DatabaseService databaseService,
                               CoordinatorProperties props) {
        this.objectMapper = objectMapper;
        this.payloadResolver = payloadResolver;
        this.databaseService = databaseService;
        this.props = props;
        this.accumulator = new BoundedAccumulator<>("scan-request", maxPendingResults(props));
    }

    @Override
    public void process(Exchange exchange) {
        String rawJson = exchange.getIn().getBody(String.class);
        if (rawJson == null || rawJson.isEmpty()) {
            return;
        }

        Try<DatabaseService.ScanRequestRecord> result = buildRecord(rawJson);
        if (result.isFailure()) {
            Throwable error = result.getCause();
            log.atError()
                    .addKeyValue("event", "scan_request_invalid")
                    .addKeyValue("error", sanitize(error.getMessage()))
                    .addKeyValue("payload_bytes", rawJson.length())
                    .log("scan request rejected");
            throw new IllegalArgumentException("scan request rejected", error);
        }

        DatabaseService.ScanRequestRecord record = result.get();
        if (!accumulator.offer(record)) {
            log.atError()
                    .addKeyValue("event", "scan_request_ingest")
                    .addKeyValue("status", "rejected")
                    .addKeyValue("reason", "accumulator_full")
                    .addKeyValue("pending_count", accumulator.size())
                    .addKeyValue("max_pending", accumulator.capacity())
                    .log("scan request accumulator rejected record");
            throw new IllegalStateException("Pending scan request accumulator is full");
        }
        flushPendingOrThrow();

    }

    private Try<DatabaseService.ScanRequestRecord> buildRecord(String rawJson) {
        return Try.of(() -> objectMapper.readValue(rawJson, ScanRequest.class))
                .map(scanRequest -> {
                    validateObservedAt(scanRequest);
                    Tuple2<String, String> resolved = resolvePayload(scanRequest);
                    return new DatabaseService.ScanRequestRecord(rawJson, resolved._1, resolved._2);
                });
    }

    private void validateObservedAt(ScanRequest scanRequest) {
        String observedAt = scanRequest.getObservedAt();
        if (observedAt == null || observedAt.isBlank()) {
            throw new IllegalArgumentException("scan request missing observed_at");
        }
        try {
            OffsetDateTime.parse(observedAt);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("scan request observed_at must be RFC3339 timestamp");
        }
    }

    private Tuple2<String, String> resolvePayload(ScanRequest scanRequest) {
        String payloadRef = scanRequest.getPayloadRef();
        if (payloadRef == null || payloadRef.isEmpty()) {
            return Tuple.of(null, null);
        }

        return Try.of(() -> payloadResolver.resolve(payloadRef, props.syncOutboxDir()))
                .map(payloadBytes -> Tuple.of(
                        new String(payloadBytes, StandardCharsets.UTF_8),
                        Sha256Utils.sha256Hex(payloadBytes)
                ))
                .getOrElseGet(error -> {
                    log.atWarn()
                            .addKeyValue("event", "scan_request_payload_resolve_failed")
                            .addKeyValue("dedupe_key", scanRequest.getDedupeKey())
                            .addKeyValue("payload_ref_scheme", payloadRefScheme(payloadRef))
                            .addKeyValue("error", sanitize(error.getMessage()))
                            .log("scan request payload resolve failed");
                    return Tuple.of(null, null);
                });
    }

    /**
     * Explicitly flushes the pending batch to the database.
     * Called automatically when batch size is reached, or can be called externally
     * on a timer to drain partial batches.
     */
    public void flushPending() {
        flushPending(false);
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
                    .addKeyValue("event", "scan_request_ingest")
                    .addKeyValue("status", "recorded")
                    .addKeyValue("count", ok.value())
                    .addKeyValue("batch_size", batch.size())
                    .log("scan request batch recorded");
            case DbResult.Empty<Integer> ignored -> log.atInfo()
                    .addKeyValue("event", "scan_request_ingest")
                    .addKeyValue("status", "recorded")
                    .addKeyValue("count", 0)
                    .addKeyValue("batch_size", batch.size())
                    .log("scan request batch recorded");
            case DbResult.Err<Integer> err -> {
                log.atError()
                        .addKeyValue("event", "scan_request_ingest")
                        .addKeyValue("status", "failed")
                        .addKeyValue("operation", err.operation())
                        .addKeyValue("batch_size", batch.size())
                        .addKeyValue("error", sanitize(err.cause().getMessage()))
                        .addKeyValue("root_cause", rootCauseSummary(err.cause()))
                        .log("scan request batch failed");
                int dropped = accumulator.requeueFront(batch);
                if (dropped > 0) {
                    log.atError()
                            .addKeyValue("event", "scan_request_ingest")
                            .addKeyValue("status", "dropped")
                            .addKeyValue("reason", "accumulator_full")
                            .addKeyValue("dropped_count", dropped)
                            .addKeyValue("pending_count", accumulator.size())
                            .addKeyValue("max_pending", accumulator.capacity())
                            .log("scan request retry records dropped");
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

    private String payloadRefScheme(String payloadRef) {
        if (payloadRef == null || payloadRef.isBlank()) {
            return "none";
        }
        int separator = payloadRef.indexOf("://");
        return separator > 0 ? payloadRef.substring(0, separator) : "unknown";
    }

    private String rootCauseSummary(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }

        String message = sanitize(root.getMessage());
        if (message.isEmpty()) {
            return root.getClass().getSimpleName();
        }
        return root.getClass().getSimpleName() + ": " + message;
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
