package com.sslproxy.coordinator.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SchemaInitializerTest {

    @Test
    void convertsJdbcUrlToPsqlUrl() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("spring.datasource.url", "jdbc:postgresql://postgres:5432/sync");
        SchemaInitializer initializer = new SchemaInitializer(
                CoordinatorProperties.DEFAULTS,
                env,
                mock(DataSource.class)
        );

        assertEquals("postgresql://postgres:5432/sync", initializer.psqlDatabaseUrl());
    }

    @Test
    void acquireSchemaLockUsesBlockingAdvisoryLock() throws Exception {
        SchemaInitializer initializer = new SchemaInitializer(
                CoordinatorProperties.DEFAULTS,
                new MockEnvironment(),
                mock(DataSource.class)
        );
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        when(connection.prepareStatement("SELECT pg_advisory_lock(?, ?)")).thenReturn(statement);

        initializer.acquireSchemaLock(connection);

        verify(statement).setInt(eq(1), anyInt());
        verify(statement).setInt(eq(2), anyInt());
        verify(statement).execute();
    }
}
