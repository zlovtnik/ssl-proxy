package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
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
    private final AdaptivePullController adaptivePullController;

    /** Tracks whether the consumer is currently suspended (avoids repeated suspend/resume calls). */
    private volatile boolean consumerSuspended = false;

    public BackpressureService(CoordinatorProperties props,
                               DatabaseService databaseService,
                               CamelContext camelContext,
                               CoordinatorMetricsService metricsService,
                               AdaptivePullController adaptivePullController) {
        this.props = props;
        this.databaseService = databaseService;
        this.camelContext = camelContext;
        this.metricsService = metricsService;
        this.adaptivePullController = adaptivePullController;
    }

    /**
     * Returns the budget (inflight watermark) computed as:
     *   ingest_batch_size * backpressure_budget_multiplier
     */
    public long budget() {
        return (long) props.ingestBatchSize() * props.backpressureBudgetMultiplier();
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
        long pendingCount = switch (databaseService.pendingLedgerCount()) {
            case DbResult.Ok<Long> ok -> ok.value();
            case DbResult.Empty<Long> ignored -> 0L;
            case DbResult.Err<Long> err -> {
                log.atWarn()
                        .addKeyValue("event", "backpressure")
                        .addKeyValue("status", "pending_count_failed")
                        .addKeyValue("operation", err.operation())
                        .addKeyValue("error", sanitize(err.cause().getMessage()))
                        .log("backpressure pending count failed");
                metricsService.recordBackpressureActive(consumerSuspended);
                yield 0L;
            }
        };
        long budget = budget();
        long recoveryThreshold = recoveryThreshold();

        metricsService.recordPendingLedgerCount(pendingCount);

        if (pendingCount >= budget) {
            if (!consumerSuspended) {
                consumerSuspended = suspendScanConsumer();
            }
            metricsService.recordBackpressureActive(consumerSuspended);
            log.atInfo()
                    .addKeyValue("event", "backpressure")
                    .addKeyValue("status", "throttled")
                    .addKeyValue("pending_count", pendingCount)
                    .addKeyValue("budget", budget)
                    .addKeyValue("multiplier", props.backpressureBudgetMultiplier())
                    .addKeyValue("consumer_suspended", consumerSuspended)
                    .log("coordinator backpressure throttled");
        } else if (pendingCount <= recoveryThreshold && consumerSuspended) {
            if (resumeScanConsumer()) {
                consumerSuspended = false;
            }
            metricsService.recordBackpressureActive(consumerSuspended);
            log.atInfo()
                    .addKeyValue("event", "backpressure")
                    .addKeyValue("status", "recovered")
                    .addKeyValue("pending_count", pendingCount)
                    .addKeyValue("recovery_threshold", recoveryThreshold)
                    .addKeyValue("consumer_resumed", !consumerSuspended)
                    .log("coordinator backpressure recovered");
        } else {
            metricsService.recordBackpressureActive(consumerSuspended);
        }

        return pendingCount;
    }

    /**
     * Suspends the scan-request-consumer route so it stops polling Kafka.
     */
    private boolean suspendScanConsumer() {
        String routeId = "scan-request-consumer";
        if (!adaptivePullController.tryLockRouteUpdate(routeId, "backpressure_suspend")) {
            log.atDebug()
                    .addKeyValue("event", "route_suspend")
                    .addKeyValue("route", routeId)
                    .addKeyValue("status", "skipped")
                    .addKeyValue("reason", "route_update_busy")
                    .log("route suspend skipped");
            return false;
        }
        try {
            camelContext.getRouteController().suspendRoute(routeId);
            log.atInfo()
                    .addKeyValue("event", "route_suspend")
                    .addKeyValue("route", routeId)
                    .addKeyValue("status", "suspended")
                    .log("route suspended");
            return true;
        } catch (Exception e) {
            log.atError()
                    .addKeyValue("event", "route_suspend")
                    .addKeyValue("route", routeId)
                    .addKeyValue("status", "failed")
                    .addKeyValue("error", e.getMessage())
                    .log("route suspend failed");
            return false;
        } finally {
            adaptivePullController.unlockRouteUpdate(routeId, "backpressure_suspend");
        }
    }

    /**
     * Resumes the scan-request-consumer route.
     */
    private boolean resumeScanConsumer() {
        String routeId = "scan-request-consumer";
        if (!adaptivePullController.tryLockRouteUpdate(routeId, "backpressure_resume")) {
            log.atDebug()
                    .addKeyValue("event", "route_resume")
                    .addKeyValue("route", routeId)
                    .addKeyValue("status", "skipped")
                    .addKeyValue("reason", "route_update_busy")
                    .log("route resume skipped");
            return false;
        }
        try {
            camelContext.getRouteController().resumeRoute(routeId);
            log.atInfo()
                    .addKeyValue("event", "route_resume")
                    .addKeyValue("route", routeId)
                    .addKeyValue("status", "resumed")
                    .log("route resumed");
            return true;
        } catch (Exception e) {
            log.atError()
                    .addKeyValue("event", "route_resume")
                    .addKeyValue("route", routeId)
                    .addKeyValue("status", "failed")
                    .addKeyValue("error", e.getMessage())
                    .log("route resume failed");
            return false;
        } finally {
            adaptivePullController.unlockRouteUpdate(routeId, "backpressure_resume");
        }
    }

    /** Returns whether the consumer route is currently suspended. */
    public boolean isConsumerSuspended() {
        return consumerSuspended;
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
