package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static com.sslproxy.coordinator.testsupport.MockitoCaptors.scanRequestRecordListCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScanRecordProcessorTest {

    @Test
    void rejectsMissingObservedAtBeforeBatching() {
        PayloadResolver payloadResolver = mock(PayloadResolver.class);
        DatabaseService databaseService = mock(DatabaseService.class);
        ScanRecordProcessor processor = new ScanRecordProcessor(
                new ObjectMapper(),
                payloadResolver,
                databaseService,
                CoordinatorProperties.DEFAULTS
        );

        assertThrows(IllegalArgumentException.class, () -> processor.process(exchangeWithBody("""
                {"stream_name":"wireless.audit","dedupe_key":"dedupe-1","payload_ref":"inline://json/e30"}
                """)));
        processor.flushPending();

        verify(payloadResolver, never()).resolve(any(), any());
        verify(databaseService, never()).recordScanRequests(any());
    }

    @Test
    void rejectsMalformedObservedAtBeforeResolvingPayload() {
        PayloadResolver payloadResolver = mock(PayloadResolver.class);
        DatabaseService databaseService = mock(DatabaseService.class);
        ScanRecordProcessor processor = new ScanRecordProcessor(
                new ObjectMapper(),
                payloadResolver,
                databaseService,
                CoordinatorProperties.DEFAULTS
        );

        assertThrows(IllegalArgumentException.class, () -> processor.process(exchangeWithBody("""
                {"stream_name":"wireless.audit","dedupe_key":"dedupe-1","payload_ref":"inline://json/e30","observed_at":"not-a-time"}
                """)));
        processor.flushPending();

        verify(payloadResolver, never()).resolve(any(), any());
        verify(databaseService, never()).recordScanRequests(any());
    }

    @Test
    void requeuesScanBatchBeforeFailFastThrow() {
        PayloadResolver payloadResolver = mock(PayloadResolver.class);
        DatabaseService databaseService = mock(DatabaseService.class);
        when(payloadResolver.resolve(any(), any())).thenReturn("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        when(databaseService.recordScanRequests(any()))
                .thenReturn(new DbResult.Err<>("recordScanRequests", new RuntimeException("database unavailable")))
                .thenReturn(new DbResult.Ok<>(1));
        ScanRecordProcessor processor = new ScanRecordProcessor(
                new ObjectMapper(),
                payloadResolver,
                databaseService,
                CoordinatorProperties.DEFAULTS
        );

        String payload = """
                {"stream_name":"wireless.audit","dedupe_key":"dedupe-1","payload_ref":"inline://json/e30","observed_at":"2026-06-01T12:00:00Z"}
                """;

        assertThrows(IllegalStateException.class, () -> processor.process(exchangeWithBody(payload)));
        processor.flushPending();

        ArgumentCaptor<List<DatabaseService.ScanRequestRecord>> records = scanRequestRecordListCaptor();
        verify(databaseService, times(2)).recordScanRequests(records.capture());
        assertEquals(1, records.getAllValues().get(1).size());
        assertEquals(payload, records.getAllValues().get(1).getFirst().requestJson());
    }

    private Exchange exchangeWithBody(String body) {
        Exchange exchange = mock(Exchange.class);
        Message message = mock(Message.class);
        when(exchange.getIn()).thenReturn(message);
        when(message.getBody(String.class)).thenReturn(body);
        return exchange;
    }

}
