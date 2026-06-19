package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

        processor.process(exchangeWithBody("""
                {"stream_name":"wireless.audit","dedupe_key":"dedupe-1","payload_ref":"inline://json/e30"}
                """));
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

        processor.process(exchangeWithBody("""
                {"stream_name":"wireless.audit","dedupe_key":"dedupe-1","payload_ref":"inline://json/e30","observed_at":"not-a-time"}
                """));
        processor.flushPending();

        verify(payloadResolver, never()).resolve(any(), any());
        verify(databaseService, never()).recordScanRequests(any());
    }

    private Exchange exchangeWithBody(String body) {
        Exchange exchange = mock(Exchange.class);
        Message message = mock(Message.class);
        when(exchange.getIn()).thenReturn(message);
        when(message.getBody(String.class)).thenReturn(body);
        return exchange;
    }
}
