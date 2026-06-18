package com.sslproxy.coordinator.processor;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.CoordinatorMetricsService;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CoordinatorProcessors {

    private static final Logger log = LoggerFactory.getLogger(CoordinatorProcessors.class);

    private final DatabaseService db;
    private final CoordinatorProperties props;
    private final CoordinatorMetricsService metrics;

    private volatile long lastShadowAuditMs = 0;

    public CoordinatorProcessors(DatabaseService db,
                                 CoordinatorProperties props,
                                 CoordinatorMetricsService metrics) {
        this.db = db;
        this.props = props;
        this.metrics = metrics;
    }

    public Processor ingest() {
        return exchange -> {
            long budget = (long) props.ingestBatchSize() * 2;
            long pendingCount = switch (db.pendingLedgerCount()) {
                case DbResult.Ok<Long> ok -> ok.value();
                case DbResult.Empty<Long> ignored -> 0L;
                case DbResult.Err<Long> err -> {
                    log.error("event=ingest_ledger status=pending_count_failed operation={} error=\"{}\"",
                            err.operation(), sanitize(err.cause().getMessage()));
                    yield 0L;
                }
            };

            if (pendingCount >= budget) {
                log.info("event=backpressure status=throttled pending_count={} budget={} ingest_batch_size={}",
                        pendingCount, budget, props.ingestBatchSize());
            }

            DbResult<Long> ingestResult = db.processIngestLedger();
            long processed = switch (ingestResult) {
                case DbResult.Ok<Long> ok -> ok.value();
                case DbResult.Empty<Long> ignored -> 0L;
                case DbResult.Err<Long> err -> {
                    log.error("event=ingest_ledger status=failed operation={} error=\"{}\"",
                            err.operation(), sanitize(err.cause().getMessage()));
                    yield 0L;
                }
            };
            boolean ingestSucceeded = !(ingestResult instanceof DbResult.Err<?>);
            metrics.recordIngestLedgerInvocation(ingestSucceeded);
            if (processed > 0) {
                log.info("event=ingest_ledger status=processed count={}", processed);
            }

            metrics.recordIngestProcessed(processed);
            exchange.getIn().setBody(processed);
        };
    }

    public Processor recoverStale() {
        return exchange -> {
            switch (db.recoverStaleDispatchedBatches()) {
                case DbResult.Ok<Integer> ok -> {
                    if (ok.value() > 0) {
                        log.info("event=stale_batch_recovery status=recovered count={}", ok.value());
                    }
                    exchange.getIn().setBody(ok.value().longValue());
                }
                case DbResult.Empty<Integer> ignored -> exchange.getIn().setBody(0L);
                case DbResult.Err<Integer> err -> {
                    log.error("event=stale_batch_recovery status=failed operation={} error=\"{}\"",
                            err.operation(), sanitize(err.cause().getMessage()));
                    exchange.getIn().setBody(0L);
                }
            }
        };
    }

    public Processor shadowAudit(long intervalMs) {
        return exchange -> {
            long now = System.currentTimeMillis();
            if (now - lastShadowAuditMs < intervalMs) {
                exchange.getIn().setBody(false);
                return;
            }

            switch (db.generateShadowAlerts()) {
                case DbResult.Ok<List<String>> ok -> {
                    List<String> alerts = ok.value();
                    if (!alerts.isEmpty()) {
                        log.info("event=shadow_audit status=alerts_generated count={} result=\"{}\"",
                                alerts.size(), alerts);
                    }
                    lastShadowAuditMs = now;
                    exchange.getIn().setBody(true);
                }
                case DbResult.Empty<List<String>> ignored -> {
                    lastShadowAuditMs = now;
                    exchange.getIn().setBody(true);
                }
                case DbResult.Err<List<String>> err -> {
                    log.error("event=shadow_audit status=failed operation={} error=\"{}\"",
                            err.operation(), sanitize(err.cause().getMessage()));
                    lastShadowAuditMs = now;
                    exchange.getIn().setBody(false);
                }
            }
        };
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
