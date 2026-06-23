package com.sslproxy.coordinator.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DataSourceDiagnosticsTest {

    @Test
    void redactsPasswordQueryParameter() {
        String sanitized = DataSourceDiagnostics.sanitizeJdbcUrl(
                "jdbc:postgresql://postgres:5432/sync?user=sync&password=secret");

        assertEquals("jdbc:postgresql://postgres:5432/sync?user=sync&password=<redacted>", sanitized);
    }

    @Test
    void redactsUserInfoPassword() {
        String sanitized = DataSourceDiagnostics.sanitizeJdbcUrl(
                "postgres://sync:secret@postgres:5432/sync");

        assertEquals("postgres://sync:<redacted>@postgres:5432/sync", sanitized);
    }

    @Test
    void redactsDescriptorPassword() {
        String sanitized = DataSourceDiagnostics.sanitizeJdbcUrl(
                "jdbc:oracle:thin:@(DESCRIPTION=(PASSWORD=secret)(HOST=db))");

        assertEquals("jdbc:oracle:thin:@(DESCRIPTION=(PASSWORD=<redacted>)(HOST=db))", sanitized);
    }
}
