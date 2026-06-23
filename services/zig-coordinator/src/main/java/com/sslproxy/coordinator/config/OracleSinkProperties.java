package com.sslproxy.coordinator.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Optional;

@ConfigurationProperties(prefix = "oracle-sink")
@Validated
public record OracleSinkProperties(
        boolean enabled,
        boolean wirelessEnabled,
        boolean schemaValidationWarnOnly,
        String conn,
        String jdbcUrl,
        String user,
        String passFile,
        String tnsAdmin,
        @Min(1) int maximumPoolSize,
        @Min(0) int minimumIdle,
        @Min(1) long connectionTimeoutMs,
        @Min(1) long validationTimeoutMs,
        @Min(1) long idleTimeoutMs,
        @Min(1) long maxLifetimeMs,
        @Min(0) long leakDetectionThresholdMs,
        String connectionInitSql,
        @Min(1) int statementTimeoutSecs,
        @Min(1) int loadMaxRetries
) {
    public boolean validateWirelessObjects() {
        return enabled && wirelessEnabled;
    }

    public String effectiveJdbcUrl() {
        if (jdbcUrl != null && !jdbcUrl.isBlank()) {
            return jdbcUrl.trim();
        }
        return "jdbc:oracle:thin:@" + requiredConn();
    }

    public String requiredConn() {
        return requiredText(conn, "ORACLE_CONN");
    }

    public Optional<String> tnsAliasForValidation() {
        if (conn != null && !conn.isBlank()) {
            return Optional.of(conn.trim());
        }
        if (jdbcUrl == null || jdbcUrl.isBlank()) {
            return Optional.empty();
        }

        String prefix = "jdbc:oracle:thin:@";
        String trimmed = jdbcUrl.trim();
        if (!trimmed.startsWith(prefix)) {
            return Optional.empty();
        }

        String target = trimmed.substring(prefix.length()).trim();
        if (target.isBlank() || target.startsWith("(") || target.contains("/") || target.contains(":")) {
            return Optional.empty();
        }
        return Optional.of(target);
    }

    public String requiredUser() {
        return requiredText(user, "ORACLE_USER");
    }

    public String requiredPassFile() {
        return requiredText(passFile, "ORACLE_PASS_FILE");
    }

    public String requiredTnsAdmin() {
        return requiredText(tnsAdmin, "TNS_ADMIN");
    }

    public String effectiveConnectionInitSql() {
        if (connectionInitSql == null || connectionInitSql.isBlank()) {
            return "SELECT 1 FROM DUAL";
        }
        return connectionInitSql.trim();
    }

    private static String requiredText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be set when oracle-sink.enabled=true");
        }
        return value.trim();
    }
}
