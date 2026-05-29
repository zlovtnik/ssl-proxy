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
                    log.warn("event=scan_request_payload_resolve_failed "
                            + "dedupe_key={} payload_ref={} error=\"{}\"",
                            scanRequest.getDedupeKey(),
                            scanRequest.getPayloadRef(),
                            e.getMessage());
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
                pending.add(record);
                shouldFlush = pending.size() >= props.getScanFetchCount();
            }

            if (shouldFlush) {
                flushPending();
            }
        } catch (Exception e) {
            log.error("event=scan_request_deserialize_failed error=\"{}\" body={}",
                    e.getMessage(),
                    rawJson.length() > 1024 ? rawJson.substring(0, 1024) + "..." : rawJson);
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
            log.info("event=scan_request_ingest status=recorded count={} batch_size={}", recorded, batch.size());
        } catch (Exception e) {
            log.error("event=scan_request_ingest status=failed batch_size={} error=\"{}\"",
                    batch.size(), e.getMessage());
            // Re-add failed records to pending for retry - at-least-once semantics
            synchronized (pending) {
                pending.addAll(0, batch);
            }
        }
    }
}
