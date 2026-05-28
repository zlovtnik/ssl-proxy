package com.sslproxy.coordinator.processor;

import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Generates shadow device alerts via the coordinator.generate_shadow_alerts() stored procedure.
 *
 * Mirrors sync_handlers.zig runShadowAudit() logic.
 * Shadow audit identifies devices that may be shadowing legitimate device identities
 * by analyzing probe request patterns and alerting on anomalies.
 *
 * Rate-limited to run at most every 10 seconds (SHADOW_AUDIT_INTERVAL_MS).
 */
@Component
public class ShadowAuditProcessor implements Processor {

    private static final Logger log = LoggerFactory.getLogger(ShadowAuditProcessor.class);

    private static final long SHADOW_AUDIT_INTERVAL_MS = 10_000;

    private final DatabaseService databaseService;

    /** Timestamp of the last successful shadow audit run (millis since epoch). */
    private volatile long lastRunTimestamp = 0;

    public ShadowAuditProcessor(DatabaseService databaseService) {
        this.databaseService = databaseService;
    }

    @Override
    public void process(Exchange exchange) {
        long now = System.currentTimeMillis();
        if (now - lastRunTimestamp < SHADOW_AUDIT_INTERVAL_MS) {
            // Rate-limited — skip this tick
            exchange.getIn().setBody(false);
            return;
        }

        try {
            var result = databaseService.generateShadowAlerts();
            if (result.isPresent() && !result.get().isEmpty()) {
                log.info("event=shadow_audit status=alerts_generated result=\"{}\"", result.get());
            }
            lastRunTimestamp = now;
            exchange.getIn().setBody(true);
        } catch (Exception e) {
            log.error("event=shadow_audit status=failed error=\"{}\"", e.getMessage());
            exchange.getIn().setBody(false);
        }
    }
}