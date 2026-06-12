package com.sslproxy.coordinator.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "oracle-sink")
@Validated
public record OracleSinkProperties(
        boolean enabled,
        String conn,
        String jdbcUrl,
        String user,
        String passFile,
        String tnsAdmin,
        @Min(1) int maximumPoolSize,
        @Min(0) int minimumIdle,
        @Min(1) long connectionTimeoutMs,
        @Min(1) long idleTimeoutMs,
        @Min(1) long maxLifetimeMs,
        @Min(1) int statementTimeoutSecs
) {
    public String effectiveJdbcUrl() {
        if (jdbcUrl != null && !jdbcUrl.isBlank()) {
            return jdbcUrl.trim();
        }
        String alias = requiredText(conn, "ORACLE_CONN");
        return "jdbc:oracle:thin:@" + alias;
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

    private static String requiredText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be set when oracle-sink.enabled=true");
        }
        return value.trim();
    }
}
