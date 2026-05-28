package com.sslproxy.coordinator.processor;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Processes the ingest ledger — transitions sync_events from pending→processing→batched.
 *
 * Mirrors scheduler.zig's processIngestLedger() call within runIteration().
 * Calls coordinator.process_ingest_ledger() stored procedure.
 */
@Component
public class IngestProcessor implements Processor {

    private static final Logger log = LoggerFactory.getLogger(IngestProcessor.class);

    private final DatabaseService databaseService;
    private final CoordinatorProperties props;

    public IngestProcessor(DatabaseService databaseService, CoordinatorProperties props) {
        this.databaseService = databaseService;
        this.props = props;
    }

    /**
     * Processes the ingest ledger. Logs the count of events processed.
     * Sets the body to the processed count (0 if none).
     */
    @Override
    public void process(Exchange exchange) {
        long budget = (long) props.getIngestBatchSize() * 2;
        long pendingCount = databaseService.pendingLedgerCount();

        if (pendingCount >= budget) {
            log.info("event=backpressure status=throttled pending_count={} budget={} ingest_batch_size={}",
                    pendingCount, budget, props.getIngestBatchSize());
        }

        long processed = databaseService.processIngestLedger();
        if (processed > 0) {
            log.info("event=ingest_ledger status=processed count={}", processed);
        }

        // Set body so the caller can check if work was done
        exchange.getIn().setBody(processed);
    }
}