package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import org.apache.camel.CamelContext;
import org.apache.camel.component.kafka.KafkaEndpoint;
import org.apache.camel.component.kafka.KafkaConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Dynamically adjusts Kafka consumer maxPollRecords based on ledger backlog.
 *
 * When pendingLedgerCount exceeds the backpressure budget's upper threshold
 * (80% of budget), maxPollRecords is shrunk to reduce fetch pressure.
 * When pendingLedgerCount falls below the lower threshold (20% of budget),
 * maxPollRecords is restored to the configured scanFetchCount / resultFetchCount.
 *
 * This affects two consumer endpoints:
 *   - scan-request-consumer (sync.scan.request)
 *   - oracle-result-consumer (sync.oracle.result)
 *
 * Only the scan consumer's fetch size adjusts; the result consumer is kept
 * at its configured value since results need to drain quickly.
 */
@Service
public class AdaptivePullController {

    private static final Logger log = LoggerFactory.getLogger(AdaptivePullController.class);

    private static final int MIN_PULL_RECORDS = 50;

    private final CoordinatorProperties props;
    private final CamelContext camelContext;
    private final DatabaseService databaseService;
    private final ConcurrentMap<String, Integer> lastAppliedMaxByRoute = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Long> lastRestartTimestampByRoute = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Boolean> routeSuspendedState = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ReentrantLock> routeUpdateLocks = new ConcurrentHashMap<>();

    public AdaptivePullController(CoordinatorProperties props,
                                  CamelContext camelContext,
                                  DatabaseService databaseService) {
        this.props = props;
        this.camelContext = camelContext;
        this.databaseService = databaseService;
    }

    /**
     * Adjusts the scan consumer's maxPollRecords based on the current pending
     * ledger count vs. the backpressure budget.
     *
     * Called once per main loop iteration at the start of the pipeline.
     */
    public void adjust() {
        long pendingCount = databaseService.pendingLedgerCount();
        long budget = (long) props.getIngestBatchSize() * props.getBackpressureBudgetMultiplier();
        long upperThreshold = (long) (budget * 0.8);
        long lowerThreshold = (long) (budget * 0.2);

        int targetPull = props.getScanFetchCount(); // default: configured value

        if (pendingCount >= upperThreshold) {
            int desired = (int) (budget - pendingCount);
            targetPull = Math.max(MIN_PULL_RECORDS, desired);
            log.info("event=adaptive_pull status=shrink pending_count={} upper_threshold={} "
                            + "new_max_poll_records={}",
                    pendingCount, upperThreshold, targetPull);
        } else if (pendingCount <= lowerThreshold) {
            targetPull = props.getScanFetchCount();
            log.info("event=adaptive_pull status=restore pending_count={} lower_threshold={} "
                            + "new_max_poll_records={}",
                    pendingCount, lowerThreshold, targetPull);
        }

        applyMaxPollRecords("scan-request-consumer", targetPull);
    }

    /**
     * Applies the maxPollRecords value to the Kafka endpoint for the given route.
     * Restarts the route so the Kafka consumer applies the updated endpoint config.
     */
    private void applyMaxPollRecords(String routeId, int maxPollRecords) {
        try {
            var route = camelContext.getRoute(routeId);
            if (route == null) {
                return;
            }

            if (route.getEndpoint() instanceof KafkaEndpoint kafkaEndpoint) {
                KafkaConfiguration config = kafkaEndpoint.getConfiguration();
                int current = config.getMaxPollRecords() != null ? config.getMaxPollRecords() : 0;
                int lastApplied = lastAppliedMaxByRoute.getOrDefault(routeId, current);

                if (current == maxPollRecords) {
                    lastAppliedMaxByRoute.put(routeId, maxPollRecords);
                    return;
                }

                int minDelta = Math.max(1, props.getAdaptivePullChangeThreshold());
                long minRestartIntervalMs = Math.max(0, props.getAdaptivePullMinRestartIntervalMs());
                long now = System.currentTimeMillis();
                long lastRestartTs = lastRestartTimestampByRoute.getOrDefault(routeId, 0L);
                long elapsedSinceRestart = now - lastRestartTs;
                boolean deltaReached = Math.abs(maxPollRecords - lastApplied) >= minDelta;
                boolean restartWindowElapsed = elapsedSinceRestart >= minRestartIntervalMs;

                if (!deltaReached && !restartWindowElapsed) {
                    log.debug("event=adaptive_pull_endpoint status=skipped_hysteresis route={} "
                                    + "current_max_poll_records={} requested_max_poll_records={} "
                                    + "last_applied_max_poll_records={} min_delta={} elapsed_ms={} "
                                    + "min_restart_interval_ms={}",
                            routeId, current, maxPollRecords, lastApplied,
                            minDelta, elapsedSinceRestart, minRestartIntervalMs);
                    return;
                }

                if (!tryLockRouteUpdate(routeId, "adaptive_pull")) {
                    log.info("event=adaptive_pull_endpoint status=skipped route={} reason=route_update_busy",
                            routeId);
                    return;
                }

                try {
                    var routeController = camelContext.getRouteController();
                    var status = routeController.getRouteStatus(routeId);
                    boolean isSuspended = status != null && status.isSuspended();
                    routeSuspendedState.put(routeId, isSuspended);

                    config.setMaxPollRecords(maxPollRecords);
                    lastAppliedMaxByRoute.put(routeId, maxPollRecords);

                    if (isSuspended) {
                        log.info("event=adaptive_pull_endpoint status=adjusted_no_restart route={} "
                                        + "old_max_poll_records={} new_max_poll_records={} "
                                        + "reason=route_suspended",
                                routeId, current, maxPollRecords);
                        return;
                    }

                    log.info("event=adaptive_pull_endpoint status=adjusted route={} "
                                    + "old_max_poll_records={} new_max_poll_records={}",
                            routeId, current, maxPollRecords);

                    routeController.stopRoute(routeId);
                    routeController.startRoute(routeId);
                    routeSuspendedState.put(routeId, false);
                    lastRestartTimestampByRoute.put(routeId, now);
                    log.info("event=adaptive_pull_endpoint status=restarted route={} elapsed_ms_since_last_restart={}",
                            routeId, elapsedSinceRestart);
                } finally {
                    unlockRouteUpdate(routeId, "adaptive_pull");
                }
            }
        } catch (Exception e) {
            log.warn("event=adaptive_pull_endpoint status=failed route={} error=\"{}\"",
                    routeId, e.getMessage());
        }
    }

    /**
     * Allows other backpressure/lifecycle logic to coordinate route updates and
     * avoid concurrent stop/start/suspend/resume sequences.
     */
    public boolean tryLockRouteUpdate(String routeId, String owner) {
        ReentrantLock lock = routeUpdateLocks.computeIfAbsent(routeId, ignored -> new ReentrantLock());
        boolean acquired = lock.tryLock();
        if (!acquired) {
            log.debug("event=route_update_lock status=busy route={} owner={}", routeId, owner);
        }
        return acquired;
    }

    public void unlockRouteUpdate(String routeId, String owner) {
        ReentrantLock lock = routeUpdateLocks.get(routeId);
        if (lock == null || !lock.isHeldByCurrentThread()) {
            return;
        }
        lock.unlock();
        log.debug("event=route_update_lock status=released route={} owner={}", routeId, owner);
    }

    public boolean isRouteUpdateInProgress(String routeId) {
        ReentrantLock lock = routeUpdateLocks.get(routeId);
        return lock != null && lock.isLocked();
    }
}
