package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import org.apache.camel.CamelContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Centralizes backpressure logic for the coordinator loop.
 *
 * Budget = ingest_batch_size * backpressure_budget_multiplier (default 4).
 * When pendingLedgerCount >= budget, the scan-request-consumer route is suspended
 * to stop ingesting new scan requests. When pendingLedgerCount falls to
 * recoveryThreshold (budget / 2), the consumer is resumed.
 *
 * The backpressure check emits Micrometer metrics and structured logs.
 */
@Service
public class BackpressureService {

    private static final Logger log = LoggerFactory.getLogger(BackpressureService.class);

    private final CoordinatorProperties props;
    private final DatabaseService databaseService;
    private final CamelContext camelContext;
    private final CoordinatorMetricsService metricsService;

    /** Tracks whether the consumer is currently suspended (avoids repeated suspend/resume calls). */
    private volatile boolean consumerSuspended = false;

    public BackpressureService(CoordinatorProperties props,
                               DatabaseService databaseService,
                               CamelContext camelContext,
                               CoordinatorMetricsService metricsService) {
        this.props = props;
        this.databaseService = databaseService;
        this.camelContext = camelContext;
        this.metricsService = metricsService;
    }

    /**
     * Returns the budget (inflight watermark) computed as:
     *   ingest_batch_size * backpressure_budget_multiplier
     */
    public long budget() {
        return (long) props.getIngestBatchSize() * props.getBackpressureBudgetMultiplier();
    }

    /**
     * Returns the recovery threshold at which a suspended consumer should be resumed:
     *   budget / 2
     */
    public long recoveryThreshold() {
        return budget() / 2;
    }

    /**
     * Runs a full backpressure check:
     * 1. Reads pendingLedgerCount
     * 2. If pending >= budget -> suspend scan-request-consumer
     * 3. If pending <= recoveryThreshold and suspended -> resume scan-request-consumer
     * 4. Records metrics and logs
     *
     * @return the pending ledger count
     */
    public long checkAndAct() {
        long pendingCount = databaseService.pendingLedgerCount();
        long budget = budget();
        long recoveryThreshold = recoveryThreshold();

        metricsService.recordPendingLedgerCount(pendingCount);

        if (pendingCount >= budget) {
            if (!consumerSuspended) {
                consumerSuspended = suspendScanConsumer();
            }
            metricsService.recordBackpressureActive(consumerSuspended);
            log.info("event=backpressure status=throttled "
                            + "pending_count={} budget={} multiplier={} consumer_suspended={}",
                    pendingCount, budget, props.getBackpressureBudgetMultiplier(), consumerSuspended);
        } else if (pendingCount <= recoveryThreshold && consumerSuspended) {
            if (resumeScanConsumer()) {
                consumerSuspended = false;
            }
            metricsService.recordBackpressureActive(consumerSuspended);
            log.info("event=backpressure status=recovered "
                            + "pending_count={} recovery_threshold={} consumer_resumed={}",
                    pendingCount, recoveryThreshold, !consumerSuspended);
        } else {
            metricsService.recordBackpressureActive(consumerSuspended);
        }

        return pendingCount;
    }

    /**
     * Suspends the scan-request-consumer route so it stops polling Kafka.
     */
    private boolean suspendScanConsumer() {
        try {
            camelContext.getRouteController().suspendRoute("scan-request-consumer");
            log.info("event=route_suspend route=scan-request-consumer status=suspended");
            return true;
        } catch (Exception e) {
            log.error("event=route_suspend route=scan-request-consumer status=failed error=\"{}\"",
                    e.getMessage());
            return false;
        }
    }

    /**
     * Resumes the scan-request-consumer route.
     */
    private boolean resumeScanConsumer() {
        try {
            camelContext.getRouteController().resumeRoute("scan-request-consumer");
            log.info("event=route_resume route=scan-request-consumer status=resumed");
            return true;
        } catch (Exception e) {
            log.error("event=route_resume route=scan-request-consumer status=failed error=\"{}\"",
                    e.getMessage());
            return false;
        }
    }

    /** Returns whether the consumer route is currently suspended. */
    public boolean isConsumerSuspended() {
        return consumerSuspended;
    }
}
