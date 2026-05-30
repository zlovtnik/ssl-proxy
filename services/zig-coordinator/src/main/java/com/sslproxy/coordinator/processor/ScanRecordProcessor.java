package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.model.ScanRequest;
import com.sslproxy.coordinator.service.DatabaseService;
import com.sslproxy.coordinator.util.Sha256Utils;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
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

    /** In-memory batch accumulator - flushes when full or on timeout. */
    private final List<DatabaseService.ScanRequestRecord> pending = new ArrayList<>();

    public ScanRecordProcessor(ObjectMapper objectMapper,
                               PayloadResolver payloadResolver,
                               DatabaseService databaseService,
                               CoordinatorProperties props) {
        this.objectMapper = objectMapper;
        this.payloadResolver = payloadResolver;
        this.databaseService = databaseService;
        this.props = props;
    }

    @Override
    public void process(Exchange exchange) {
        String rawJson = exchange.getIn().getBody(String.class);
        if (rawJson == null || rawJson.isEmpty()) {
            return;
        }

        try {
            ScanRequest scanRequest = objectMapper.readValue(rawJson, ScanRequest.class);

            String resolvedPayloadJson = null;
            String payloadSha256 = null;

            if (scanRequest.getPayloadRef() != null && !scanRequest.getPayloadRef().isEmpty()) {
                try {
                    byte[] payloadBytes = payloadResolver.resolve(
                            scanRequest.getPayloadRef(),
                            props.getSyncOutboxDir()
                    );
                    resolvedPayloadJson = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);
                    payloadSha256 = Sha256Utils.sha256Hex(payloadBytes);
                } catch (Exception e) {
                    log.atWarn()
                            .addKeyValue("event", "scan_request_payload_resolve_failed")
                            .addKeyValue("dedupe_key", scanRequest.getDedupeKey())
                            .addKeyValue("payload_ref_scheme", payloadRefScheme(scanRequest.getPayloadRef()))
                            .addKeyValue("error", sanitize(e.getMessage()))
                            .log("scan request payload resolve failed");
                    // Zig stores null payload/sha256 on resolve failure - match that behavior
                    resolvedPayloadJson = null;
                    payloadSha256 = null;
                }
            }

            DatabaseService.ScanRequestRecord record = new DatabaseService.ScanRequestRecord(
                    rawJson,
                    resolvedPayloadJson,
                    payloadSha256
            );

            boolean shouldFlush;
            synchronized (pending) {
                int maxPending = maxPendingResults();
                if (pending.size() >= maxPending) {
                    pending.remove(0);
                    log.atError()
                            .addKeyValue("event", "scan_request_ingest")
                            .addKeyValue("status", "dropped_oldest")
                            .addKeyValue("reason", "pending_limit")
                            .addKeyValue("pending_count", pending.size())
                            .addKeyValue("max_pending", maxPending)
                            .log("scan request accumulator dropped oldest record");
                }
                pending.add(record);
                shouldFlush = pending.size() >= props.getScanFetchCount();
            }

            if (shouldFlush) {
                flushPending();
            }
        } catch (Exception e) {
            log.atError()
                    .addKeyValue("event", "scan_request_deserialize_failed")
                    .addKeyValue("error", sanitize(e.getMessage()))
                    .addKeyValue("payload_bytes", rawJson.length())
                    .log("scan request deserialize failed");
        }
    }

    /**
     * Explicitly flushes the pending batch to the database.
     * Called automatically when batch size is reached, or can be called externally
     * on a timer to drain partial batches.
     */
    public void flushPending() {
        List<DatabaseService.ScanRequestRecord> batch;
        synchronized (pending) {
            if (pending.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pending);
            pending.clear();
        }

        try {
            int recorded = databaseService.recordScanRequests(batch);
            log.atInfo()
                    .addKeyValue("event", "scan_request_ingest")
                    .addKeyValue("status", "recorded")
                    .addKeyValue("count", recorded)
                    .addKeyValue("batch_size", batch.size())
                    .log("scan request batch recorded");
        } catch (Exception e) {
            log.atError()
                    .addKeyValue("event", "scan_request_ingest")
                    .addKeyValue("status", "failed")
                    .addKeyValue("batch_size", batch.size())
                    .addKeyValue("error", sanitize(e.getMessage()))
                    .log("scan request batch failed");
            // Re-add failed records for retry while enforcing a bounded accumulator.
            synchronized (pending) {
                int maxPending = maxPendingResults();
                int available = Math.max(0, maxPending - pending.size());
                int toRequeue = Math.min(batch.size(), available);

                if (toRequeue > 0) {
                    pending.addAll(0, batch.subList(0, toRequeue));
                }

                int dropped = batch.size() - toRequeue;
                if (dropped > 0) {
                    log.atError()
                            .addKeyValue("event", "scan_request_ingest")
                            .addKeyValue("status", "dropped")
                            .addKeyValue("reason", "pending_limit")
                            .addKeyValue("dropped_count", dropped)
                            .addKeyValue("pending_count", pending.size())
                            .addKeyValue("max_pending", maxPending)
                            .log("scan request retry records dropped");
                }
            }
        }
    }

    private int maxPendingResults() {
        int multiplier = Math.max(1, props.getBackpressureBudgetMultiplier());
        return Math.max(props.getScanFetchCount(), props.getScanFetchCount() * multiplier);
    }

    private String payloadRefScheme(String payloadRef) {
        if (payloadRef == null || payloadRef.isBlank()) {
            return "none";
        }
        int separator = payloadRef.indexOf("://");
        return separator > 0 ? payloadRef.substring(0, separator) : "unknown";
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
