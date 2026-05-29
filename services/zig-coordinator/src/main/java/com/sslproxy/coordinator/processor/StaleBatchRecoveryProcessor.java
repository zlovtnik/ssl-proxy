package com.sslproxy.coordinator.processor;

import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Recovers stale dispatched batches whose lease has expired.
 *
 * Mirrors sync_handlers.zig recoverStaleDispatchedBatches().
 * Calls coordinator.recover_stale_dispatched_batches() stored procedure.
 *
 * Leases are defined by batch_dispatch_lease_seconds in config.
 * Batches whose lease has expired are returned to 'batched' state for redispatch,
 * as long as they haven't exceeded batch_max_attempts.
 */
@Component
public class StaleBatchRecoveryProcessor implements Processor {

    private static final Logger log = LoggerFactory.getLogger(StaleBatchRecoveryProcessor.class);

    private final DatabaseService databaseService;

    public StaleBatchRecoveryProcessor(DatabaseService databaseService) {
        this.databaseService = databaseService;
    }

    @Override
    public void process(Exchange exchange) {
        try {
            int recovered = databaseService.recoverStaleDispatchedBatches();
            if (recovered > 0) {
                log.info("event=stale_batch_recovery status=recovered count={}", recovered);
            }
            exchange.getIn().setBody((long) recovered);
        } catch (Exception e) {
            log.error("event=stale_batch_recovery status=failed error=\"{}\"", e.getMessage());
            exchange.getIn().setBody(0L);
        }
    }
}