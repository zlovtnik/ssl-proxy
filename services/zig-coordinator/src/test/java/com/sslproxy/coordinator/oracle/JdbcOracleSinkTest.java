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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JdbcOracleSinkTest {

    @Test
    void schemaValidationRejectsMissingObjects() throws Exception {
        JdbcOracleSink sink = sink();
        SchemaQuery query = schemaQuery(List.of());

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> sink.validateSchemaObjects(query.connection()));

        assertTrue(error.getMessage().contains("Oracle sink schema objects unavailable"));
        assertTrue(error.getMessage().contains("PROCEDURE WIRELESS_UPSERT_SENSOR"));
        assertTrue(error.getMessage().contains("TABLE WIRELESS_AUDIT_FRAMES"));
        assertTrue(error.getMessage().contains("sql/oracle.sql"));
    }

    @Test
    void schemaValidationAcceptsVisibleValidObjects() throws Exception {
        JdbcOracleSink sink = sink();
        SchemaQuery query = schemaQuery(visibleObjects(JdbcOracleSink.REQUIRED_SCHEMA_OBJECTS, "VALID"));

        assertDoesNotThrow(() -> sink.validateSchemaObjects(query.connection()));
    }

    @Test
    void schemaValidationAcceptsCoreObjectsWhenWirelessDisabled() throws Exception {
        JdbcOracleSink sink = sink(false);
        SchemaQuery query = schemaQuery(visibleObjects(JdbcOracleSink.CORE_SCHEMA_OBJECTS, "VALID"));

        assertDoesNotThrow(() -> sink.validateSchemaObjects(query.connection()));
    }

    @Test
    void schemaValidationReportsInvalidObjects() throws Exception {
        JdbcOracleSink sink = sink();
        List<VisibleOracleObject> objects = visibleObjects(JdbcOracleSink.REQUIRED_SCHEMA_OBJECTS, "VALID");
        objects.set(0, new VisibleOracleObject(JdbcOracleSink.REQUIRED_SCHEMA_OBJECTS.getFirst(), "INVALID"));
        SchemaQuery query = schemaQuery(objects);

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> sink.validateSchemaObjects(query.connection()));

        assertTrue(error.getMessage().contains("invalid=[TABLE PROXY_EVENTS status=INVALID]"));
    }

    @Test
    void schemaValidationAppliesStatementTimeout() throws Exception {
        JdbcOracleSink sink = sink();
        SchemaQuery query = schemaQuery(visibleObjects(JdbcOracleSink.REQUIRED_SCHEMA_OBJECTS, "VALID"));

        sink.validateSchemaObjects(query.connection());

        verify(query.statement()).setQueryTimeout(5);
    }

    private JdbcOracleSink sink() {
        return sink(true);
    }

    private JdbcOracleSink sink(boolean wirelessEnabled) {
        return new JdbcOracleSink(
                mock(OracleConnectionFactory.class),
                props(wirelessEnabled),
                new ObjectMapper(),
                mock(ObservationRegistry.class)
        );
    }

    private SchemaQuery schemaQuery(List<VisibleOracleObject> objects) throws Exception {
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        AtomicInteger rowIndex = new AtomicInteger(-1);

        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenAnswer(invocation -> rowIndex.incrementAndGet() < objects.size());
        when(resultSet.getString("OBJECT_NAME"))
                .thenAnswer(invocation -> objects.get(rowIndex.get()).requirement().name());
        when(resultSet.getString("OBJECT_TYPE"))
                .thenAnswer(invocation -> objects.get(rowIndex.get()).requirement().type());
        when(resultSet.getString("STATUS")).thenAnswer(invocation -> objects.get(rowIndex.get()).status());

        return new SchemaQuery(connection, statement);
    }

    private List<VisibleOracleObject> visibleObjects(List<JdbcOracleSink.OracleObjectRequirement> objects, String status) {
        return objects.stream()
                .map(requirement -> new VisibleOracleObject(requirement, status))
                .collect(java.util.stream.Collectors.toCollection(java.util.ArrayList::new));
    }

    private OracleSinkProperties props(boolean wirelessEnabled) {
        return new OracleSinkProperties(
                true,
                wirelessEnabled,
                false,
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
                5,
                3
        );
    }

    private record SchemaQuery(Connection connection, PreparedStatement statement) {
    }

    private record VisibleOracleObject(JdbcOracleSink.OracleObjectRequirement requirement, String status) {
    }
}
