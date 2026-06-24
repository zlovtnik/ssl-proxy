package com.sslproxy.coordinator.config;

import com.sslproxy.coordinator.oracle.OracleConnectionFactory;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

@Component
public class DataSourceDiagnostics implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSourceDiagnostics.class);

    private final DataSource dataSource;
    private final OracleSinkProperties oracleSinkProperties;
    private final OracleConnectionFactory oracleConnectionFactory;

    public DataSourceDiagnostics(DataSource dataSource,
                                 OracleSinkProperties oracleSinkProperties,
                                 OracleConnectionFactory oracleConnectionFactory) {
        this.dataSource = dataSource;
        this.oracleSinkProperties = oracleSinkProperties;
        this.oracleConnectionFactory = oracleConnectionFactory;
    }

    @Override
    public void run(ApplicationArguments args) {
        logDataSource("postgres", dataSource);
        logOracle();
    }

    private void logDataSource(String name, DataSource ds) {
        if (ds instanceof HikariDataSource hikari) {
            log.info("[datasource:{}] url={} pool={}",
                    name,
                    sanitizeJdbcUrl(hikari.getJdbcUrl()),
                    sanitizeValue(hikari.getPoolName()));
        } else {
            log.info("[datasource:{}] type={}", name, ds.getClass().getName());
        }

        try (Connection connection = ds.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            log.info("[datasource:{}] connected ok db={} version={} url={}",
                    name,
                    sanitizeValue(meta.getDatabaseProductName()),
                    sanitizeValue(meta.getDatabaseProductVersion()),
                    sanitizeJdbcUrl(meta.getURL()));
        } catch (SQLException e) {
            log.error("[datasource:{}] connection FAILED error={}", name, sanitizeJdbcUrl(e.getMessage()));
        }
    }

    private void logOracle() {
        if (!oracleSinkProperties.enabled()) {
            log.info("[datasource:oracle] status=disabled");
            return;
        }

        try {
            log.info("[datasource:oracle] url={} pool={}",
                    sanitizeJdbcUrl(oracleSinkProperties.effectiveJdbcUrl()),
                    "coordinator-oracle");
            oracleConnectionFactory.checkConnectivity();
            log.info("[datasource:oracle] connected ok");
        } catch (Exception e) {
            log.error("[datasource:oracle] connection FAILED error_class={}", e.getClass().getSimpleName());
        }
    }

    static String sanitizeJdbcUrl(String value) {
        String sanitized = sanitizeValue(value);
        sanitized = sanitized.replaceAll("(?i)(//[^:/@\\s]+:)[^@/?\\s]+@", "$1<redacted>@");
        sanitized = sanitized.replaceAll("(?i)([?&;](?:password|pass|pwd)=)[^&;\\s]*", "$1<redacted>");
        sanitized = sanitized.replaceAll("(?i)(\\b(?:password|pass|pwd)\\s*=\\s*)[^),;\\s]+", "$1<redacted>");
        return sanitized;
    }

    private static String sanitizeValue(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.replace('\n', ' ').replace('\r', ' ');
    }
}
