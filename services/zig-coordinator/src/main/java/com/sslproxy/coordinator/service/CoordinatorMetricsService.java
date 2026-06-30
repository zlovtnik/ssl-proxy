package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
 *   - coordinator_route_running             (gauge)
 *   - coordinator_route_suspended           (gauge)
 */
@Service
public class CoordinatorMetricsService {

    private static final Logger log = LoggerFactory.getLogger(CoordinatorMetricsService.class);

    private final CoordinatorProperties props;
    private final AtomicLong pendingLedgerGauge = new AtomicLong(0);
    private final AtomicLong backpressureActiveGauge = new AtomicLong(0);
    private final AtomicLong ingestLedgerLastSuccessTimestampSeconds = new AtomicLong(0);
    private final Map<String, RouteStateMeters> routeStateMeters = new ConcurrentHashMap<>();

    private final Counter loopAttemptsCounter;
    private final Counter ingestLedgerInvocationsCounter;
    private final Counter ingestProcessedCounter;
    private final Counter batchesDispatchedCounter;
    private final Counter heartbeatCounter;

    private volatile long lastHeartbeatLogAtMillis = 0;

    public CoordinatorMetricsService(MeterRegistry registry, CoordinatorProperties props) {
        this.props = props;

        Gauge.builder("coordinator.pending.ledger.count", pendingLedgerGauge, value -> value.get())
                .description("Number of pending ledger entries")
                .register(registry);

        Gauge.builder("coordinator.backpressure.active", backpressureActiveGauge, value -> value.get())
                .description("1 if backpressure is throttling, 0 otherwise")
                .register(registry);

        loopAttemptsCounter = Counter.builder("coordinator.loop.attempts.total")
                .description("Total main loop iterations")
                .register(registry);

        ingestLedgerInvocationsCounter = Counter.builder("coordinator.ingest.ledger.invocations.total")
                .description("Total process_ingest_ledger invocations")
                .register(registry);

        Gauge.builder("coordinator.ingest.ledger.last.success.timestamp.seconds",
                        ingestLedgerLastSuccessTimestampSeconds, value -> value.get())
                .description("Unix timestamp in seconds for the last successful process_ingest_ledger invocation")
                .baseUnit("seconds")
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

        registerRouteStateMeters(registry, "scan", "scan-request-consumer");
        registerRouteStateMeters(registry, "result", "oracle-result-consumer");
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

    public void recordIngestLedgerInvocation(boolean success) {
        ingestLedgerInvocationsCounter.increment();
        if (success) {
            ingestLedgerLastSuccessTimestampSeconds.set(System.currentTimeMillis() / 1000);
        }
    }

    public void recordIngestProcessed(long count) {
        if (count > 0) {
            ingestProcessedCounter.increment(count);
        }
    }

    public void recordBatchDispatched() {
        batchesDispatchedCounter.increment();
    }

    public void recordRouteState(String role, String routeId, boolean running, boolean suspended) {
        RouteStateMeters meters = routeStateMeters.get(routeStateKey(role, routeId));
        if (meters == null) {
            return;
        }
        meters.running().set(running ? 1 : 0);
        meters.suspended().set(suspended ? 1 : 0);
    }

    /**
     * Heartbeat - increments counter every loop and rate-limits INFO logging.
     * Called once per main loop iteration after all steps complete.
     */
    public void heartbeat() {
        heartbeatCounter.increment();
        long now = System.currentTimeMillis();
        long intervalMs = Math.max(0, props.heartbeatLogIntervalMs());
        if (intervalMs > 0 && now - lastHeartbeatLogAtMillis < intervalMs) {
            return;
        }
        lastHeartbeatLogAtMillis = now;

        log.atInfo()
                .addKeyValue("event", "heartbeat")
                .addKeyValue("loop_count", (long) loopAttemptsCounter.count())
                .addKeyValue("pending_ledger_count", pendingLedgerGauge.get())
                .addKeyValue("backpressure_active", backpressureActiveGauge.get())
                .log("coordinator heartbeat");
    }

    private void registerRouteStateMeters(MeterRegistry registry, String role, String routeId) {
        RouteStateMeters meters = new RouteStateMeters(new AtomicLong(0), new AtomicLong(0));
        routeStateMeters.put(routeStateKey(role, routeId), meters);

        Gauge.builder("coordinator.route.running", meters.running(), value -> value.get())
                .description("1 if the coordinator route is running, 0 otherwise")
                .tag("role", role)
                .tag("route", routeId)
                .register(registry);

        Gauge.builder("coordinator.route.suspended", meters.suspended(), value -> value.get())
                .description("1 if the coordinator route is suspended, 0 otherwise")
                .tag("role", role)
                .tag("route", routeId)
                .register(registry);
    }

    private String routeStateKey(String role, String routeId) {
        return role + ":" + routeId;
    }

    private record RouteStateMeters(AtomicLong running, AtomicLong suspended) {}
}
