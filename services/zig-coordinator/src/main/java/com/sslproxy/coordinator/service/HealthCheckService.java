package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.OracleSinkProperties;
import com.sslproxy.coordinator.oracle.OracleConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Health check service that validates connectivity to Postgres and Redpanda.
 * Corresponds to the healthcheck logic in scheduler.zig
 */
@Service
public class HealthCheckService {

    private static final Logger log = LoggerFactory.getLogger(HealthCheckService.class);

    private final DatabaseService db;
    private final OracleSinkProperties oracleSinkProperties;
    private final OracleConnectionFactory oracleConnectionFactory;

    public HealthCheckService(DatabaseService db,
                              OracleSinkProperties oracleSinkProperties,
                              OracleConnectionFactory oracleConnectionFactory) {
        this.db = db;
        this.oracleSinkProperties = oracleSinkProperties;
        this.oracleConnectionFactory = oracleConnectionFactory;
    }

    /**
     * Runs a complete health check. Throws RuntimeException on failure.
     */
    public void checkHealth() {
        log.info("event=healthcheck status=start");
        checkPostgres();
        checkPostgresCursors();
        checkOracle();
        log.info("event=healthcheck status=ok");
    }

    /**
     * Checks Postgres connectivity.
     */
    private void checkPostgres() {
        try {
            db.checkConnectivity().orElseThrow();
            log.info("event=healthcheck_step step=check_postgres status=ok");
        } catch (Exception e) {
            log.error("event=healthcheck_step step=check_postgres status=error error={}", e.getMessage());
            throw new RuntimeException("Postgres connectivity check failed", e);
        }
    }

    /**
     * Checks that cursors can be ensured for all configured streams.
     */
    private void checkPostgresCursors() {
        try {
            db.ensureAllCursors().orElseThrow();
            log.info("event=healthcheck_step step=check_cursors status=ok");
        } catch (Exception e) {
            log.error("event=healthcheck_step step=check_cursors status=error error={}", e.getMessage());
            throw new RuntimeException("Cursor check failed", e);
        }
    }

    private void checkOracle() {
        if (!oracleSinkProperties.enabled()) {
            log.info("event=healthcheck_step step=check_oracle status=skipped");
            return;
        }
        try {
            oracleConnectionFactory.checkConnectivity();
            log.info("event=healthcheck_step step=check_oracle status=ok");
        } catch (Exception e) {
            log.error("event=healthcheck_step step=check_oracle status=error error={}", e.getMessage());
            throw new RuntimeException("Oracle connectivity check failed", e);
        }
    }
}
