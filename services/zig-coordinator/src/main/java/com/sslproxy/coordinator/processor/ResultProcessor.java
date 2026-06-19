package com.sslproxy.coordinator.processor;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.BoundedAccumulator;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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
    private final BoundedAccumulator<String> accumulator;

    public ResultProcessor(DatabaseService databaseService, CoordinatorProperties props) {
        this.databaseService = databaseService;
        this.props = props;
        this.accumulator = new BoundedAccumulator<>("oracle-result", maxPendingResults(props));
    }

    @Override
    public void process(Exchange exchange) {
        String resultJson = exchange.getIn().getBody(String.class);
        if (resultJson == null || resultJson.isEmpty()) {
            return;
        }

        if (!accumulator.offer(resultJson)) {
            log.error("event=batch_result_ingest status=rejected reason=accumulator_full "
                    + "pending_count={} max_pending={}", accumulator.size(), accumulator.capacity());
            throw new IllegalStateException("Pending result accumulator is full");
        }

        flushPendingOrThrow();
    }

    /**
     * Flushes the accumulated result batch to the database.
     * Can be called externally on a timer to drain partial batches.
     */
    public void flushPending() {
        flushPending(false);
    }

    private void flushPendingOrThrow() {
        flushPending(true);
    }

    private void flushPending(boolean failOnError) {
        List<String> batch = accumulator.drain(props.resultFetchCount());
        if (batch.isEmpty()) {
            return;
        }

        switch (databaseService.processBatchResults(batch)) {
            case DbResult.Ok<Integer> ok ->
                    log.info("event=batch_result_ingest status=processed count={} batch_size={}", ok.value(), batch.size());
            case DbResult.Empty<Integer> ignored ->
                    log.info("event=batch_result_ingest status=processed count=0 batch_size={}", batch.size());
            case DbResult.Err<Integer> err -> {
                log.error("event=batch_result_ingest status=failed operation={} batch_size={} error=\"{}\"",
                        err.operation(), batch.size(), sanitize(err.cause().getMessage()));
                int dropped = accumulator.requeueFront(batch);
                if (dropped > 0) {
                    log.error("event=batch_result_ingest status=dropped reason=accumulator_full "
                                    + "dropped_count={} pending_count={} max_pending={}",
                            dropped, accumulator.size(), accumulator.capacity());
                }
                if (failOnError) {
                    throw new IllegalStateException(err.operation(), err.cause());
                }
            }
        }
    }

    private static int maxPendingResults(CoordinatorProperties props) {
        int multiplier = Math.max(1, props.backpressureBudgetMultiplier());
        return Math.max(1, props.resultFetchCount()) * multiplier;
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
