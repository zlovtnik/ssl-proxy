package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import org.apache.camel.CamelContext;
import org.apache.camel.component.kafka.KafkaEndpoint;
import org.apache.camel.component.kafka.KafkaConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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
            targetPull = Math.max(MIN_PULL_RECORDS, (int) Math.max(MIN_PULL_RECORDS, budget - pendingCount));
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
     * Walks endpoints on the route to find the Kafka consumer endpoint.
     */
    private void applyMaxPollRecords(String routeId, int maxPollRecords) {
        try {
            var route = camelContext.getRoute(routeId);
            if (route == null) return;

            for (var endpoint : camelContext.getEndpoints()) {
                if (endpoint instanceof KafkaEndpoint kafkaEndpoint) {
                    String epUri = endpoint.getEndpointUri();
                    // Only adjust the scan consumer endpoint
                    if (epUri.contains("scan.request")) {
                        KafkaConfiguration config = kafkaEndpoint.getConfiguration();
                        int current = config.getMaxPollRecords() != null ? config.getMaxPollRecords() : 0;
                        if (current != maxPollRecords) {
                            config.setMaxPollRecords(maxPollRecords);
                            log.info("event=adaptive_pull_endpoint status=adjusted route={} "
                                            + "old_max_poll_records={} new_max_poll_records={}",
                                    routeId, current, maxPollRecords);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("event=adaptive_pull_endpoint status=failed route={} error=\"{}\"",
                    routeId, e.getMessage());
        }
    }
}