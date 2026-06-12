package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.ProducerTemplate;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BatchDispatchProcessorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void rejectsBlankPayloadRefBeforePublishing() {
        DatabaseService databaseService = mock(DatabaseService.class);
        ProducerTemplate producerTemplate = mock(ProducerTemplate.class);
        Exchange exchange = mock(Exchange.class);
        Message message = mock(Message.class);
        when(exchange.getIn()).thenReturn(message);

        String batchJson = """
                {
                  "job_id":"job-1",
                  "batch_id":"11111111-1111-1111-1111-111111111111",
                  "batch_no":0,
                  "stream_name":"wireless.audit",
                  "payload_ref":"",
                  "attempt":1
                }
                """;
        when(databaseService.getNextBatch()).thenReturn(new DbResult.Ok<>(batchJson));
        when(databaseService.markBatchDispatchFailed(eq(batchJson), eq("payload_ref must not be empty")))
                .thenReturn(new DbResult.Ok<>("{}"));

        BatchDispatchProcessor processor = new BatchDispatchProcessor(
                databaseService,
                CoordinatorProperties.DEFAULTS,
                objectMapper,
                producerTemplate
        );

        processor.process(exchange);

        verify(producerTemplate, never()).sendBody(anyString(), any(Object.class));
        verify(databaseService).markBatchDispatchFailed(batchJson, "payload_ref must not be empty");
        verify(message).setBody(false);
    }
}
