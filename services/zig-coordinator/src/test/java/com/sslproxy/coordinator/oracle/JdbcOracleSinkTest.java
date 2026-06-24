package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.OracleSinkProperties;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.Month;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    void rawUuidBytesPacksCanonicalUuid() throws Exception {
        byte[] raw = JdbcOracleSink.rawUuidBytes("00112233-4455-6677-8899-aabbccddeeff");

        assertArrayEquals(new byte[] {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
        }, raw);
    }

    @Test
    void rawUuidBytesAcceptsCompactHexUuid() throws Exception {
        byte[] raw = JdbcOracleSink.rawUuidBytes("00112233445566778899aabbccddeeff");

        assertArrayEquals(JdbcOracleSink.rawUuidBytes("00112233-4455-6677-8899-aabbccddeeff"), raw);
    }

    @Test
    void rawUuidBytesRejectsInvalidUuid() {
        SQLException error = assertThrows(SQLException.class, () -> JdbcOracleSink.rawUuidBytes("batch-1"));

        assertEquals("invalid UUID value for RAW(16)", error.getMessage());
    }

    @Test
    void eventTimestampUtcNormalizesAndTruncatesToMillis() {
        OffsetDateTime eventTime = OffsetDateTime.parse("2026-06-01T08:00:00.123456-04:00");

        var utc = JdbcOracleSink.eventTimestampUtc(eventTime);

        assertEquals(2026, utc.getYear());
        assertEquals(Month.JUNE, utc.getMonth());
        assertEquals(1, utc.getDayOfMonth());
        assertEquals(12, utc.getHour());
        assertEquals(0, utc.getMinute());
        assertEquals(0, utc.getSecond());
        assertEquals(123_000_000, utc.getNano());
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
                1_000,
                30_000,
                "SELECT 1 FROM DUAL",
                5,
                3
        );
    }

    private record SchemaQuery(Connection connection, PreparedStatement statement) {
    }

    private record VisibleOracleObject(JdbcOracleSink.OracleObjectRequirement requirement, String status) {
    }
}
