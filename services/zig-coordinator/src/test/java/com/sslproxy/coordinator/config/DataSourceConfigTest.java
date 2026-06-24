package com.sslproxy.coordinator.config;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

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

    @Test
    void preservesLiteralPlusInCredentials() {
        DataSourceConfig.DatabaseUrl databaseUrl =
                DataSourceConfig.normalizeDatabaseUrl("postgres://sync:abc+def@postgres:5432/sync");

        assertEquals("abc+def", databaseUrl.password());
    }

    @Test
    void decodesPercentEncodedCredentialsWithoutFormDecoding() {
        DataSourceConfig.DatabaseUrl databaseUrl =
                DataSourceConfig.normalizeDatabaseUrl("postgres://sync:p%40ss%2Bword@postgres:5432/sync");

        assertEquals("p@ss+word", databaseUrl.password());
    }

    @Test
    void databaseUrlCredentialsOverrideSeparatePostgresCredentials() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("DATABASE_URL", "postgres://url_user:url_secret@postgres:5432/sync")
                .withProperty("POSTGRES_USER", "sync")
                .withProperty("POSTGRES_PASSWORD", "stale_secret");

        try (HikariDataSource dataSource = new DataSourceConfig().dataSource(environment)) {
            assertEquals("jdbc:postgresql://postgres:5432/sync", dataSource.getJdbcUrl());
            assertEquals("url_user", dataSource.getUsername());
            assertEquals("url_secret", dataSource.getPassword());
        }
    }

    @Test
    void separatePostgresCredentialsAreUsedWhenJdbcUrlHasNoCredentials() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("DATABASE_URL", "jdbc:postgresql://postgres:5432/sync")
                .withProperty("POSTGRES_USER", "sync")
                .withProperty("POSTGRES_PASSWORD", "postgres_secret");

        try (HikariDataSource dataSource = new DataSourceConfig().dataSource(environment)) {
            assertEquals("jdbc:postgresql://postgres:5432/sync", dataSource.getJdbcUrl());
            assertEquals("sync", dataSource.getUsername());
            assertEquals("postgres_secret", dataSource.getPassword());
        }
    }
}
