package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.OracleSinkProperties;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JdbcOracleSinkTest {

    @Test
    void schemaValidationRejectsMissingObjects() throws Exception {
        JdbcOracleSink sink = sink();
        Connection connection = connectionWithObjects(List.of());

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> sink.validateSchemaObjects(connection));

        assertTrue(error.getMessage().contains("Oracle sink schema objects unavailable"));
        assertTrue(error.getMessage().contains("PROCEDURE WIRELESS_UPSERT_SENSOR"));
        assertTrue(error.getMessage().contains("TABLE WIRELESS_AUDIT_FRAMES"));
        assertTrue(error.getMessage().contains("sql/oracle.sql"));
    }

    @Test
    void schemaValidationAcceptsVisibleValidObjects() throws Exception {
        JdbcOracleSink sink = sink();
        Connection connection = connectionWithObjects(JdbcOracleSink.REQUIRED_SCHEMA_OBJECTS);

        assertDoesNotThrow(() -> sink.validateSchemaObjects(connection));
    }

    private JdbcOracleSink sink() {
        return new JdbcOracleSink(
                mock(OracleConnectionFactory.class),
                props(),
                new ObjectMapper(),
                mock(ObservationRegistry.class)
        );
    }

    private Connection connectionWithObjects(List<JdbcOracleSink.OracleObjectRequirement> objects) throws Exception {
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        AtomicInteger rowIndex = new AtomicInteger(-1);

        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenAnswer(invocation -> rowIndex.incrementAndGet() < objects.size());
        when(resultSet.getString("OBJECT_NAME")).thenAnswer(invocation -> objects.get(rowIndex.get()).name());
        when(resultSet.getString("OBJECT_TYPE")).thenAnswer(invocation -> objects.get(rowIndex.get()).type());
        when(resultSet.getString("STATUS")).thenReturn("VALID");

        return connection;
    }

    private OracleSinkProperties props() {
        return new OracleSinkProperties(
                true,
                "mainerc_high",
                "",
                "USCIS_APP",
                "/run/secrets/oracle_password.txt",
                "/app/wallet",
                1,
                0,
                1_000,
                1_000,
                1_000,
                5
        );
    }
}
