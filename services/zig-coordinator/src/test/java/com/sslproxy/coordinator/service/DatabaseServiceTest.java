package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PGobject;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.mockito.ArgumentCaptor;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DatabaseServiceTest {

    @Test
    void recordScanRequestsBindsTypedArraysAndFreesThem() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        DatabaseService service = new DatabaseService(jdbc, withStreamNames(List.of("proxy.events", "wireless.audit")));

        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        Array requestArray = mock(Array.class);
        Array payloadArray = mock(Array.class);
        Array shaArray = mock(Array.class);
        Array streamArray = mock(Array.class);

        when(connection.createArrayOf(eq("jsonb"), any(Object[].class)))
                .thenReturn(requestArray, payloadArray);
        when(connection.createArrayOf(eq("text"), any(Object[].class)))
                .thenReturn(shaArray, streamArray);
        when(connection.prepareStatement("SELECT coordinator.record_scan_request_batch(?, ?, ?, ?)::text"))
                .thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(1)).thenReturn("2");
        stubJdbcExecute(jdbc, connection);

        String requestOne = "{\"stream_name\":\"proxy.events\",\"dedupe_key\":\"dedupe-1\","
                + "\"payload_ref\":\"inline://one\",\"observed_at\":\"2026-05-30T12:00:00Z\"}";
        String payloadOne = "{\"type\":\"audit\",\"message\":\"quote \\\" slash \\\\ comma, brace {\"}";
        String requestTwo = "{\"stream_name\":\"wireless.audit\",\"dedupe_key\":\"dedupe-2\","
                + "\"payload_ref\":\"inline://two\",\"observed_at\":\"2026-05-30T12:01:00Z\"}";

        int recorded = service.recordScanRequests(List.of(
                new DatabaseService.ScanRequestRecord(requestOne, payloadOne, "sha-1"),
                new DatabaseService.ScanRequestRecord(requestTwo, null, null)
        )).orElseThrow();

        assertEquals(2, recorded);
        ArgumentCaptor<Object[]> jsonbArrays = ArgumentCaptor.forClass(Object[].class);
        verify(connection, times(2)).createArrayOf(eq("jsonb"), jsonbArrays.capture());
        assertJsonb(requestOne, jsonbArrays.getAllValues().get(0)[0]);
        assertJsonb(requestTwo, jsonbArrays.getAllValues().get(0)[1]);
        assertJsonb(payloadOne, jsonbArrays.getAllValues().get(1)[0]);
        assertNull(jsonbArrays.getAllValues().get(1)[1]);

        ArgumentCaptor<Object[]> textArrays = ArgumentCaptor.forClass(Object[].class);
        verify(connection, times(2)).createArrayOf(eq("text"), textArrays.capture());
        assertArrayEquals(new Object[]{"sha-1", null}, textArrays.getAllValues().get(0));
        assertArrayEquals(new Object[]{"proxy.events", "wireless.audit"}, textArrays.getAllValues().get(1));
        verify(statement).setArray(1, requestArray);
        verify(statement).setArray(2, payloadArray);
        verify(statement).setArray(3, shaArray);
        verify(statement).setArray(4, streamArray);
        verify(requestArray).free();
        verify(payloadArray).free();
        verify(shaArray).free();
        verify(streamArray).free();
    }

    @Test
    void processBatchResultsBindsTypedJsonbArrayAndFreesIt() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        DatabaseService service = new DatabaseService(jdbc, CoordinatorProperties.DEFAULTS);

        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        ResultSet resultSet = mock(ResultSet.class);
        Array resultArray = mock(Array.class);

        when(connection.createArrayOf(eq("jsonb"), any(Object[].class))).thenReturn(resultArray);
        when(connection.prepareStatement("SELECT coordinator.process_batch_results(?)::text"))
                .thenReturn(statement);
        when(statement.executeQuery()).thenReturn(resultSet);
        when(resultSet.next()).thenReturn(true);
        when(resultSet.getString(1)).thenReturn("1");
        stubJdbcExecute(jdbc, connection);

        String resultJson = "{\"batch_id\":\"6b8c2a30-5f1e-4cfb-9e45-7e046d832340\","
                + "\"status\":\"success\",\"checksum\":\"a,b{c}\"}";

        int processed = service.processBatchResults(List.of(resultJson)).orElseThrow();

        assertEquals(1, processed);
        ArgumentCaptor<Object[]> jsonbArrays = ArgumentCaptor.forClass(Object[].class);
        verify(connection).createArrayOf(eq("jsonb"), jsonbArrays.capture());
        assertJsonb(resultJson, jsonbArrays.getValue()[0]);
        verify(statement).setArray(1, resultArray);
        verify(resultArray).free();
    }

    private static void stubJdbcExecute(JdbcTemplate jdbc, Connection connection) {
        when(jdbc.execute(anyConnectionCallback())).thenAnswer(invocation -> {
            ConnectionCallback<?> callback = invocation.getArgument(0);
            return callback.doInConnection(connection);
        });
    }

    @SuppressWarnings("unchecked")
    private static ConnectionCallback<String> anyConnectionCallback() {
        return any(ConnectionCallback.class);
    }

    private static CoordinatorProperties withStreamNames(List<String> streamNames) {
        CoordinatorProperties d = CoordinatorProperties.DEFAULTS;
        return new CoordinatorProperties(
            d.streamName(),
            streamNames,
            d.oracleStreamNames(),
            d.scanTopic(),
            d.loadTopic(),
            d.resultTopic(),
            d.databaseUrl(),
            d.syncRedpandaUrl(),
            d.redpandaTopicManifestFile(),
            d.syncSchemaFile(),
            d.redpandaPublishTimeoutMs(),
            d.auditStreamName(),
            d.resultStreamName(),
            d.scanConsumer(),
            d.loadConsumer(),
            d.resultConsumer(),
            d.wirelessBacklogStreamName(),
            d.wirelessMacStreamName(),
            d.wirelessNetworksStreamName(),
            d.wirelessProbeStreamName(),
            d.wirelessBacklogSaveConsumer(),
            d.wirelessBacklogListConsumer(),
            d.wirelessBacklogSyncedConsumer(),
            d.wirelessBacklogPruneConsumer(),
            d.wirelessMacLookupConsumer(),
            d.wirelessNetworksAuthorizedConsumer(),
            d.wirelessProbeFlushConsumer(),
            d.wirelessBacklogListReplyTopic(),
            d.wirelessBacklogPruneReplyTopic(),
            d.wirelessMacLookupReplyTopic(),
            d.wirelessNetworksAuthorizedReplyTopic(),
            d.wirelessRawArchiveEnabled(),
            d.wirelessRawPayloadHotDays(),
            d.syncEventRowRetentionDays(),
            d.syncEventTombstoneRetentionDays(),
            d.wirelessRawArchiveBatchSize(),
            d.retentionPruneBatchSize(),
            d.wirelessRawArchiveIntervalMs(),
            d.retentionMaintenanceIntervalMs(),
            d.wirelessRawArchiveBucket(),
            d.minioEndpoint(),
            d.minioAccessKeyId(),
            d.minioSecretAccessKey(),
            d.syncOutboxDir(),
            d.scanMaxAttempts(),
            d.scanRetryBackoffSeconds(),
            d.batchDispatchLeaseSeconds(),
            d.batchMaxAttempts(),
            d.scanFetchCount(),
            d.resultFetchCount(),
            d.scanConsumersCount(),
            d.resultConsumersCount(),
            d.wirelessConsumersCount(),
            d.wirelessMaxPollRecords(),
            d.ingestBatchSize(),
            d.dispatchBatchSize(),
            d.idleSleepMs(),
            d.idleSleepBackoffMs(),
            d.backpressureBudgetMultiplier(),
            d.adaptivePullChangeThreshold(),
            d.adaptivePullMinRestartIntervalMs(),
            d.redpandaLagMetricsEnabled(),
            d.redpandaLagMetricsPollIntervalMs(),
            d.redpandaLagMetricsTimeoutMs(),
            d.heartbeatLogIntervalMs(),
            d.mode()
        );
    }

    private static void assertJsonb(String expectedValue, Object raw) {
        PGobject object = assertInstanceOf(PGobject.class, raw);
        assertEquals("jsonb", object.getType());
        assertEquals(expectedValue, object.getValue());
    }
}
