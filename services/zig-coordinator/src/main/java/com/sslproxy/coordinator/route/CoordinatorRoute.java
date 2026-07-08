package com.sslproxy.coordinator.route;

import com.sslproxy.coordinator.processor.BatchDispatchProcessor;
import com.sslproxy.coordinator.processor.CoordinatorProcessors;
import com.sslproxy.coordinator.service.AdaptivePullController;
import com.sslproxy.coordinator.service.BackpressureService;
import com.sslproxy.coordinator.service.CoordinatorMetricsService;
import org.apache.camel.CamelContext;
import org.apache.camel.LoggingLevel;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Main coordinator route that implements the core loop from scheduler.zig.
 *
 * The loop runs on a timer and orchestrates:
 * 1. Adaptive pull window - shrink Kafka consumer fetch size when DB falls behind
 * 2. Backpressure check - suspend scan consumer when pending ledger exceeds budget
 * 3. Ingest ledger processing - processIngestLedger()
 * 4. Stale batch recovery - recoverStaleDispatchedBatches()
 * 5. Batch dispatch - getNextBatch() -> publish to sync.oracle.load
 * 6. Shadow audit - generateShadowAlerts() (rate-limited to 10s intervals)
 * 7. Heartbeat & metrics - record counters, emit heartbeat log
 *
 * Steps 2 and 6 are standalone Kafka consumers (ScanRequestRoute, OracleResultRoute)
 * and are kept as lightweight pass-throughs in the main loop for monitoring parity.
 */
@Component
public class CoordinatorRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(CoordinatorRoute.class);

    private final CoordinatorProcessors coordinatorProcessors;
    private final BatchDispatchProcessor batchDispatchProcessor;

    private final BackpressureService backpressureService;
    private final AdaptivePullController adaptivePullController;
    private final CoordinatorMetricsService metricsService;
    private final CamelContext camelContext;

    public CoordinatorRoute(CoordinatorProcessors coordinatorProcessors,
                            BatchDispatchProcessor batchDispatchProcessor,
                            BackpressureService backpressureService,
                            AdaptivePullController adaptivePullController,
                            CoordinatorMetricsService metricsService,
                            CamelContext camelContext) {
        this.coordinatorProcessors = coordinatorProcessors;
        this.batchDispatchProcessor = batchDispatchProcessor;
        this.backpressureService = backpressureService;
        this.adaptivePullController = adaptivePullController;
        this.metricsService = metricsService;
        this.camelContext = camelContext;
    }

    @Override
    public void configure() {
        // Error handler for the main route - log and continue
        onException(Exception.class)
                .log("event=route_error error=${exception.message}")
                .continued(true);

        // =====================================================================
        // Main loop - runs on a timer matching the Zig idle_sleep pattern.
        //
        // Phase 4 additions:
        //   1. direct:adaptivePull     <- shrink Kafka fetch when DB is behind
        //   2. direct:backpressureV2   <- centralised BackpressureService (budget * 4)
        //   3. direct:heartbeat        <- Micrometer metrics + heartbeat log
        // =====================================================================
        from("timer:coordinator-loop?period={{coordinator.idle-sleep-ms}}&daemon=true")
                .routeId("coordinator-main-loop")
                .log(LoggingLevel.TRACE, "event=iteration_start")
                .to("direct:adaptivePull")
                .to("direct:backpressureV2")
                .to("direct:processScanRequests")
                .to("direct:processIngest")
                .to("direct:recoverStaleBatches")
                .to("direct:dispatchBatches")
                .to("direct:handleResults")
                .to("direct:shadowAudit")
                .to("direct:wirelessOperations")
                .to("direct:heartbeat");

        // =====================================================================
        // Adaptive pull - shrink Kafka consumer maxPollRecords when DB falls
        // behind the backpressure budget thresholds.
        // =====================================================================
        from("direct:adaptivePull")
                .routeId("coordinator-adaptive-pull")
                .process(exchange -> {
                    adaptivePullController.adjust();
                });

        // =====================================================================
        // Backpressure - uses BackpressureService with budget = ingest_batch_size * 4.
        //
        // When pendingLedgerCount >= budget, the scan-request-consumer route is
        // suspended to stop ingesting new scan requests. It is resumed when the
        // count falls to recoveryThreshold (budget / 2).
        // =====================================================================
        from("direct:backpressureV2")
                .routeId("coordinator-backpressure")
                .process(exchange -> {
                    long pendingCount = backpressureService.checkAndAct();
                    exchange.setProperty("pendingLedgerCount", pendingCount);
                    exchange.setProperty("backpressureBudget", backpressureService.budget());
                    exchange.setProperty("backpressureActive", backpressureService.isConsumerSuspended());
                });

        // =====================================================================
        // Scan request processing - lightweight pass-through.
        // The actual Kafka consumption and DB ingestion is handled by
        // ScanRequestRoute (scan-request-consumer) running independently.
        // =====================================================================
        from("direct:processScanRequests")
                .routeId("coordinator-scan-requests")
                .log(LoggingLevel.TRACE, "event=scan_requests status=delegated");

        // =====================================================================
        // Ingest processing - delegates to CoordinatorProcessors.ingest()
        // Mirrors scheduler.zig: processIngestLedger() call
        // =====================================================================
        from("direct:processIngest")
                .routeId("coordinator-ingest")
                .process(coordinatorProcessors.ingest());

        // =====================================================================
        // Stale batch recovery - delegates to CoordinatorProcessors.recoverStale()
        // Mirrors scheduler.zig: recoverStaleDispatchedBatches() call
        // =====================================================================
        from("direct:recoverStaleBatches")
                .routeId("coordinator-stale-recovery")
                .process(coordinatorProcessors.recoverStale());

        // =====================================================================
        // Batch dispatch loop - dispatches up to dispatch_batch_size batches.
        // Records metrics for each successfully dispatched batch.
        // Mirrors scheduler.zig: dispatchNextBatch() called in a loop
        // =====================================================================
        from("direct:dispatchBatches")
                .routeId("coordinator-dispatch")
                .loop(simple("{{coordinator.dispatch-batch-size}}"))
                    .process(countingDispatch(batchDispatchProcessor, metricsService))
                    .choice()
                        .when(simple("${body} == false"))
                            .log(LoggingLevel.TRACE, "event=batch_dispatch status=no_more_batches")
                        .endChoice()
                    .end()
                .end();

        // =====================================================================
        // Result handling - lightweight pass-through.
        // The actual Kafka consumption and DB ingestion is handled by
        // OracleResultRoute (oracle-result-consumer) running independently.
        // =====================================================================
        from("direct:handleResults")
                .routeId("coordinator-results")
                .log(LoggingLevel.TRACE, "event=results status=delegated");

        // =====================================================================
        // Shadow audit - rate-limited to 10 second intervals
        // Uses CoordinatorProcessors.shadowAudit() for rate-limit state
        // Mirrors scheduler.zig: runShadowAudit() with SHADOW_AUDIT_INTERVAL_MS
        // =====================================================================
        from("direct:shadowAudit")
                .routeId("coordinator-shadow-audit")
                .process(coordinatorProcessors.shadowAudit(10_000))
                .choice()
                    .when(simple("${body} == true"))
                        .log(LoggingLevel.INFO, "event=shadow_audit status=completed")
                    .endChoice()
                .end();

        // =====================================================================
        // Wireless operations - delegated to independent Kafka consumer routes
        // in WirelessRoutes.java (7 wireless handlers each with their own
        // consumer group). This pass-through provides loop timing parity with
        // the Zig wireless_handlers.zig run() call.
        // =====================================================================
        from("direct:wirelessOperations")
                .routeId("coordinator-wireless")
                .log(LoggingLevel.TRACE, "event=wireless status=delegated consumers=7");

        // =====================================================================
        // Heartbeat - records loop counter and emits heartbeat log with
        // pending ledger count, backpressure status, and other metrics.
        // =====================================================================
        from("direct:heartbeat")
                .routeId("coordinator-heartbeat")
                .process(exchange -> {
                    metricsService.incrementLoopCounter();
                    recordRouteState("scan", "scan-request-consumer");
                    recordRouteState("result", "oracle-result-consumer");
                    metricsService.heartbeat();
                });
    }

    private void recordRouteState(String role, String routeId) {
        try {
            var status = camelContext.getRouteController().getRouteStatus(routeId);
            metricsService.recordRouteState(
                    role,
                    routeId,
                    status != null && status.isStarted(),
                    status != null && status.isSuspended()
            );
        } catch (Exception e) {
            log.atWarn()
                    .addKeyValue("event", "route_state_metrics")
                    .addKeyValue("status", "failed")
                    .addKeyValue("role", role)
                    .addKeyValue("route", routeId)
                    .addKeyValue("error", e.getMessage())
                    .log("route state metric update failed");
        }
    }

    private static Processor countingDispatch(Processor delegate, CoordinatorMetricsService metrics) {
        return exchange -> {
            delegate.process(exchange);
            if (Boolean.TRUE.equals(exchange.getIn().getBody(Boolean.class))) {
                metrics.recordBatchDispatched();
            }
        };
    }
}
