package com.sslproxy.coordinator.processor;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Processes Oracle batch results from sync.oracle.result Kafka topic.
 *
 * Accumulates result JSONs into batches and flushes to DB via
 * DatabaseService.processBatchResults().
 *
 * Replaces sync_handlers.zig handleResults() logic.
 */
@Component
public class ResultProcessor implements Processor {

    private static final Logger log = LoggerFactory.getLogger(ResultProcessor.class);

    private final DatabaseService databaseService;
    private final CoordinatorProperties props;

    /** In-memory batch accumulator. */
    private final List<String> pending = new ArrayList<>();

    public ResultProcessor(DatabaseService databaseService, CoordinatorProperties props) {
        this.databaseService = databaseService;
        this.props = props;
    }

    @Override
    public void process(Exchange exchange) {
        String resultJson = exchange.getIn().getBody(String.class);
        if (resultJson == null || resultJson.isEmpty()) {
            return;
        }

        boolean shouldFlush;
        synchronized (pending) {
            int maxPending = maxPendingResults();
            if (pending.size() >= maxPending) {
                log.error("event=batch_result_ingest status=rejected reason=pending_limit "
                        + "pending_count={} max_pending={}", pending.size(), maxPending);
                throw new IllegalStateException("Pending result accumulator is full");
            }
            pending.add(resultJson);
            shouldFlush = pending.size() >= props.getResultFetchCount();
        }

        if (shouldFlush) {
            flushPending();
        }
    }

    /**
     * Flushes the accumulated result batch to the database.
     * Can be called externally on a timer to drain partial batches.
     */
    public void flushPending() {
        List<String> batch;
        synchronized (pending) {
            if (pending.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pending);
            pending.clear();
        }

        try {
            int processed = databaseService.processBatchResults(batch);
            log.info("event=batch_result_ingest status=processed count={} batch_size={}", processed, batch.size());
        } catch (Exception e) {
            log.error("event=batch_result_ingest status=failed batch_size={} error=\"{}\"",
                    batch.size(), e.getMessage());
            // Re-add for retry - at-least-once semantics
            synchronized (pending) {
                pending.addAll(0, batch);
            }
            throw new IllegalStateException("Failed to process batch results", e);
        }
    }

    private int maxPendingResults() {
        int multiplier = Math.max(1, props.getBackpressureBudgetMultiplier());
        return Math.max(props.getResultFetchCount(), props.getResultFetchCount() * multiplier);
    }
}
