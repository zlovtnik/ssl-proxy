package com.sslproxy.coordinator.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DataSourceConfigTest {

    @Test
    void leavesJdbcPostgresUrlUnchanged() {
        DataSourceConfig.DatabaseUrl databaseUrl =
                DataSourceConfig.normalizeDatabaseUrl("jdbc:postgresql://postgres:5432/sync");

        assertEquals("jdbc:postgresql://postgres:5432/sync", databaseUrl.jdbcUrl());
    }

    @Test
    void convertsPostgresUrlToJdbcUrlAndExtractsCredentials() {
        DataSourceConfig.DatabaseUrl databaseUrl =
                DataSourceConfig.normalizeDatabaseUrl("postgres://sync:secret@postgres:5432/sync");

        assertEquals("jdbc:postgresql://postgres:5432/sync", databaseUrl.jdbcUrl());
        assertEquals("sync", databaseUrl.username());
        assertEquals("secret", databaseUrl.password());
    }

    @Test
    void preservesPostgresUrlQueryParameters() {
        DataSourceConfig.DatabaseUrl databaseUrl =
                DataSourceConfig.normalizeDatabaseUrl("postgres://sync:secret@postgres:5432/sync?sslmode=require");

        assertEquals("jdbc:postgresql://postgres:5432/sync?sslmode=require", databaseUrl.jdbcUrl());
    }
}
