package com.sslproxy.coordinator.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Registers and exposes Micrometer meters for the coordinator loop.
 *
 * Meters published to /actuator/prometheus automatically:
 *   - coordinator_pending_ledger_count      (gauge)
 *   - coordinator_loop_attempts_total       (counter)
 *   - coordinator_ingest_processed_total    (counter)
 *   - coordinator_batches_dispatched_total  (counter)
 *   - coordinator_backpressure_active       (gauge)
 *   - coordinator_heartbeat_total           (counter)
 */
@Service
public class CoordinatorMetricsService {

    private static final Logger log = LoggerFactory.getLogger(CoordinatorMetricsService.class);

    private final AtomicLong pendingLedgerGauge = new AtomicLong(0);
    private final AtomicLong backpressureActiveGauge = new AtomicLong(0);

    private final Counter loopAttemptsCounter;
    private final Counter ingestProcessedCounter;
    private final Counter batchesDispatchedCounter;
    private final Counter heartbeatCounter;

    public CoordinatorMetricsService(MeterRegistry registry) {
        Gauge.builder("coordinator.pending.ledger.count", pendingLedgerGauge, AtomicLong::get)
                .description("Number of pending ledger entries")
                .register(registry);

        Gauge.builder("coordinator.backpressure.active", backpressureActiveGauge, AtomicLong::get)
                .description("1 if backpressure is throttling, 0 otherwise")
                .register(registry);

        loopAttemptsCounter = Counter.builder("coordinator.loop.attempts.total")
                .description("Total main loop iterations")
                .register(registry);

        ingestProcessedCounter = Counter.builder("coordinator.ingest.processed.total")
                .description("Total events processed by ingest ledger")
                .register(registry);

        batchesDispatchedCounter = Counter.builder("coordinator.batches.dispatched.total")
                .description("Total batches dispatched to Oracle worker")
                .register(registry);

        heartbeatCounter = Counter.builder("coordinator.heartbeat.total")
                .description("Heartbeat counter, incremented each loop iteration")
                .register(registry);
    }

    public void recordPendingLedgerCount(long count) {
        pendingLedgerGauge.set(count);
    }

    public void recordBackpressureActive(boolean active) {
        backpressureActiveGauge.set(active ? 1 : 0);
    }

    public void incrementLoopCounter() {
        loopAttemptsCounter.increment();
    }

    public void recordIngestProcessed(long count) {
        if (count > 0) {
            ingestProcessedCounter.increment(count);
        }
    }

    public void recordBatchDispatched() {
        batchesDispatchedCounter.increment();
    }

    /**
     * Heartbeat — increments counter and logs at INFO so it appears in structured logs.
     * Called once per main loop iteration after all steps complete.
     */
    public void heartbeat() {
        heartbeatCounter.increment();
        log.info("event=heartbeat loop_count={} pending_ledger_count={} backpressure_active={}",
                (long) loopAttemptsCounter.count(),
                pendingLedgerGauge.get(),
                backpressureActiveGauge.get());
    }
}