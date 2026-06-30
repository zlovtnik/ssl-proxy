package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static com.sslproxy.coordinator.testsupport.MockitoCaptors.scanRequestRecordListCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PayloadAuditRecordProcessorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void translatesPayloadAuditIntoScanRequestRecord() throws Exception {
        DatabaseService databaseService = mock(DatabaseService.class);
        when(databaseService.recordScanRequests(any())).thenReturn(new DbResult.Ok<>(1));
        PayloadAuditRecordProcessor processor = new PayloadAuditRecordProcessor(
                objectMapper,
                databaseService,
                CoordinatorProperties.DEFAULTS
        );

        String payload = """
                {
                  "observed_at":"2026-06-01T12:00:00Z",
                  "host":"api.example",
                  "method":"POST",
                  "path":"/login",
                  "content_type":"application/json",
                  "body":{"password":"[REDACTED]"}
                }
                """;

        processor.process(exchangeWithBody(payload));

        ArgumentCaptor<List<DatabaseService.ScanRequestRecord>> records = scanRequestRecordListCaptor();
        verify(databaseService).recordScanRequests(records.capture());
        DatabaseService.ScanRequestRecord record = records.getValue().getFirst();
        var request = objectMapper.readTree(record.requestJson());

        assertEquals("proxy.payload_audit", request.get("stream_name").asText());
        assertEquals("2026-06-01T12:00:00Z", request.get("observed_at").asText());
        assertTrue(request.get("payload_ref").asText().startsWith("inline://json/"));
        assertEquals(payload, record.payloadJson());
    }

    @Test
    void rejectsPayloadAuditWithoutObservedAt() {
        DatabaseService databaseService = mock(DatabaseService.class);
        PayloadAuditRecordProcessor processor = new PayloadAuditRecordProcessor(
                objectMapper,
                databaseService,
                CoordinatorProperties.DEFAULTS
        );

        processor.process(exchangeWithBody("{\"host\":\"api.example\"}"));

        verify(databaseService, never()).recordScanRequests(any());
    }

    @Test
    void requeuesPayloadAuditBatchBeforeFailFastThrow() {
        DatabaseService databaseService = mock(DatabaseService.class);
        when(databaseService.recordScanRequests(any()))
                .thenReturn(new DbResult.Err<>("recordScanRequests", new RuntimeException("database unavailable")))
                .thenReturn(new DbResult.Ok<>(1));
        PayloadAuditRecordProcessor processor = new PayloadAuditRecordProcessor(
                objectMapper,
                databaseService,
                CoordinatorProperties.DEFAULTS
        );

        String payload = """
                {
                  "observed_at":"2026-06-01T12:00:00Z",
                  "host":"api.example",
                  "method":"POST",
                  "path":"/login",
                  "content_type":"application/json"
                }
                """;

        assertThrows(IllegalStateException.class, () -> processor.process(exchangeWithBody(payload)));
        processor.flushPending();

        ArgumentCaptor<List<DatabaseService.ScanRequestRecord>> records = scanRequestRecordListCaptor();
        verify(databaseService, times(2)).recordScanRequests(records.capture());
        assertEquals(1, records.getAllValues().get(1).size());
        assertEquals(payload, records.getAllValues().get(1).getFirst().payloadJson());
    }

    private Exchange exchangeWithBody(String body) {
        Exchange exchange = mock(Exchange.class);
        Message message = mock(Message.class);
        when(exchange.getIn()).thenReturn(message);
        when(message.getBody(String.class)).thenReturn(body);
        return exchange;
    }

}
