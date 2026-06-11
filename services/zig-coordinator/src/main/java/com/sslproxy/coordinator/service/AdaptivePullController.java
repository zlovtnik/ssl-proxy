package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.fp.RouteAdjustment;
import org.apache.camel.CamelContext;
import org.apache.camel.component.kafka.KafkaConfiguration;
import org.apache.camel.component.kafka.KafkaEndpoint;
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
    private static final String SCAN_ROUTE_ID = "scan-request-consumer";

    private final CoordinatorProperties props;
    private final CamelContext camelContext;
    private final DatabaseService databaseService;
    private final ConcurrentMap<String, RouteState> routeStates = new ConcurrentHashMap<>();
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
        long pendingCount = switch (databaseService.pendingLedgerCount()) {
            case DbResult.Ok<Long> ok -> ok.value();
            case DbResult.Empty<Long> ignored -> 0L;
            case DbResult.Err<Long> err -> {
                log.warn("event=adaptive_pull status=pending_count_failed operation={} error=\"{}\"",
                        err.operation(), sanitize(err.cause().getMessage()));
                yield -1L;
            }
        };
        if (pendingCount < 0) {
            return;
        }

        long budget = (long) props.ingestBatchSize() * props.backpressureBudgetMultiplier();
        adjustRoute(SCAN_ROUTE_ID, pendingCount, budget);
    }

    public static RouteAdjustment decideAdjustment(long pendingCount,
                                                   long budget,
                                                   int configuredFetchCount,
                                                   int currentMaxPollRecords,
                                                   int lastApplied,
                                                   int minDelta,
                                                   long elapsedSinceRestartMs,
                                                   long minRestartIntervalMs) {
        long safeBudget = Math.max(1L, budget);
        long upperThreshold = Math.max(1L, (long) (safeBudget * 0.8));
        long lowerThreshold = Math.max(0L, (long) (safeBudget * 0.2));

        if (pendingCount >= upperThreshold) {
            long desiredLong = Math.max(MIN_PULL_RECORDS, safeBudget - pendingCount);
            int desired = (int) Math.min(Integer.MAX_VALUE, desiredLong);
            boolean deltaReached = Math.abs(desired - lastApplied) >= Math.max(1, minDelta);
            boolean windowElapsed = elapsedSinceRestartMs >= Math.max(0, minRestartIntervalMs);
            if (!deltaReached && !windowElapsed) {
                return new RouteAdjustment.NoChange("hysteresis");
            }
            return new RouteAdjustment.Shrink(desired, pendingCount, upperThreshold);
        }

        if (pendingCount <= lowerThreshold && currentMaxPollRecords != configuredFetchCount) {
            boolean deltaReached = Math.abs(configuredFetchCount - lastApplied) >= Math.max(1, minDelta);
            boolean windowElapsed = elapsedSinceRestartMs >= Math.max(0, minRestartIntervalMs);
            if (!deltaReached && !windowElapsed) {
                return new RouteAdjustment.NoChange("hysteresis");
            }
            return new RouteAdjustment.Restore(configuredFetchCount, pendingCount, lowerThreshold);
        }

        return new RouteAdjustment.NoChange("within_bounds");
    }

    private void adjustRoute(String routeId, long pendingCount, long budget) {
        try {
            var route = camelContext.getRoute(routeId);
            if (route == null || !(route.getEndpoint() instanceof KafkaEndpoint kafkaEndpoint)) {
                return;
            }

            KafkaConfiguration config = kafkaEndpoint.getConfiguration();
            int current = config.getMaxPollRecords() != null
                    ? config.getMaxPollRecords()
                    : props.scanFetchCount();
            long now = System.currentTimeMillis();
            RouteState state = routeStates.getOrDefault(routeId, RouteState.initial(current));
            RouteAdjustment decision = decideAdjustment(
                    pendingCount,
                    budget,
                    props.scanFetchCount(),
                    current,
                    state.lastAppliedMaxPollRecords(),
                    props.adaptivePullChangeThreshold(),
                    now - state.lastRestartTimestampMs(),
                    props.adaptivePullMinRestartIntervalMs()
            );

            switch (decision) {
                case RouteAdjustment.NoChange noChange ->
                        log.debug("event=adaptive_pull status=no_change reason={}", noChange.reason());
                case RouteAdjustment.Shrink shrink -> {
                    log.info("event=adaptive_pull status=shrink pending_count={} upper_threshold={} "
                                    + "new_max_poll_records={}",
                            shrink.pendingCount(), shrink.upperThreshold(), shrink.newMaxPollRecords());
                    applyMaxPollRecords(routeId, config, current, shrink.newMaxPollRecords(), now);
                }
                case RouteAdjustment.Restore restore -> {
                    log.info("event=adaptive_pull status=restore pending_count={} lower_threshold={} "
                                    + "new_max_poll_records={}",
                            restore.pendingCount(), restore.lowerThreshold(), restore.newMaxPollRecords());
                    applyMaxPollRecords(routeId, config, current, restore.newMaxPollRecords(), now);
                }
            }
        } catch (Exception e) {
            log.warn("event=adaptive_pull_endpoint status=failed route={} error=\"{}\"",
                    routeId, sanitize(e.getMessage()));
        }
    }

    /**
     * Applies the maxPollRecords value to the Kafka endpoint for the given route.
     * Restarts the route so the Kafka consumer applies the updated endpoint config.
     */
    private void applyMaxPollRecords(String routeId,
                                     KafkaConfiguration config,
                                     int current,
                                     int maxPollRecords,
                                     long now) throws Exception {
        if (current == maxPollRecords) {
            routeStates.compute(routeId, (ignored, state) ->
                    (state == null ? RouteState.initial(current) : state).withApplied(maxPollRecords));
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

            config.setMaxPollRecords(maxPollRecords);

            if (isSuspended) {
                routeStates.compute(routeId, (ignored, state) ->
                        (state == null ? RouteState.initial(current) : state)
                                .withApplied(maxPollRecords)
                                .withSuspended(true));
                log.info("event=adaptive_pull_endpoint status=adjusted_no_restart route={} "
                                + "old_max_poll_records={} new_max_poll_records={} reason=route_suspended",
                        routeId, current, maxPollRecords);
                return;
            }

            log.info("event=adaptive_pull_endpoint status=adjusted route={} "
                            + "old_max_poll_records={} new_max_poll_records={}",
                    routeId, current, maxPollRecords);

            routeController.stopRoute(routeId);
            routeController.startRoute(routeId);
            routeStates.compute(routeId, (ignored, state) ->
                    (state == null ? RouteState.initial(current) : state)
                            .withApplied(maxPollRecords)
                            .withRestart(now)
                            .withSuspended(false));
            log.info("event=adaptive_pull_endpoint status=restarted route={}", routeId);
        } finally {
            unlockRouteUpdate(routeId, "adaptive_pull");
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

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }

    private record RouteState(int lastAppliedMaxPollRecords,
                              long lastRestartTimestampMs,
                              boolean suspended) {
        private static RouteState initial(int currentMaxPollRecords) {
            return new RouteState(currentMaxPollRecords, 0L, false);
        }

        private RouteState withApplied(int maxPollRecords) {
            return new RouteState(maxPollRecords, lastRestartTimestampMs, suspended);
        }

        private RouteState withRestart(long timestampMs) {
            return new RouteState(lastAppliedMaxPollRecords, timestampMs, suspended);
        }

        private RouteState withSuspended(boolean isSuspended) {
            return new RouteState(lastAppliedMaxPollRecords, lastRestartTimestampMs, isSuspended);
        }
    }
}
