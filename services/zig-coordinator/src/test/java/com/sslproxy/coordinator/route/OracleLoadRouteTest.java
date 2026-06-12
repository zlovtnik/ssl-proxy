package com.sslproxy.coordinator.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.oracle.OracleLoad;
import com.sslproxy.coordinator.oracle.OracleLoadHandler;
import com.sslproxy.coordinator.oracle.OracleResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OracleLoadRouteTest {

    @Test
    void handlerFailurePreservesParsedIdentifiers() throws Exception {
        OracleLoadHandler loadHandler = mock(OracleLoadHandler.class);
        when(loadHandler.handle(any(OracleLoad.class))).thenThrow(new IllegalStateException("sink failed"));
        OracleLoadRoute route = new OracleLoadRoute(new ObjectMapper(), loadHandler);

        OracleResult result = route.handleLoadMessage("""
                {
                  "job_id": "job-1",
                  "batch_id": "batch-1",
                  "batch_no": 7,
                  "stream_name": "wireless.audit",
                  "payload_ref": "inline://json/W10"
                }
                """);

        assertEquals("failed", result.status());
        assertEquals("job-1", result.jobId());
        assertEquals("batch-1", result.batchId());
        assertTrue(result.errorText().contains("handle sync.oracle.load message"));
    }

    @Test
    void transientHandlerFailureIsRetryable() throws Exception {
        OracleLoadHandler loadHandler = mock(OracleLoadHandler.class);
        when(loadHandler.handle(any(OracleLoad.class))).thenThrow(new IllegalStateException("ORA-03114 not connected"));
        OracleLoadRoute route = new OracleLoadRoute(new ObjectMapper(), loadHandler);

        OracleResult result = route.handleLoadMessage("""
                {
                  "job_id": "job-1",
                  "batch_id": "batch-1",
                  "batch_no": 7,
                  "stream_name": "wireless.audit",
                  "payload_ref": "inline://json/W10"
                }
                """);

        assertEquals("failed", result.status());
        assertEquals("retryable", result.errorClass());
        assertTrue(result.retryable());
    }

    @Test
    void decodeFailureUsesEmptyIdentifiers() {
        OracleLoadRoute route = new OracleLoadRoute(new ObjectMapper(), mock(OracleLoadHandler.class));

        OracleResult result = route.handleLoadMessage("{");

        assertEquals("failed", result.status());
        assertEquals("", result.jobId());
        assertEquals("", result.batchId());
        assertEquals("permanent", result.errorClass());
        assertEquals(false, result.retryable());
        assertTrue(result.errorText().contains("decode sync.oracle.load message"));
    }
}
