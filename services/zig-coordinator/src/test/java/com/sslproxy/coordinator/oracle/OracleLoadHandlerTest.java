package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OracleLoadHandlerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void handlesProxyEventsLoadWithBlockedRollup(@TempDir Path outbox) {
        FakeSink sink = new FakeSink();
        OracleLoadHandler handler = handler(outbox, sink);
        String payload = """
                [{
                  "type":"connect",
                  "time":"2026-06-01T12:00:00Z",
                  "host":"ads.example",
                  "bytes_up":10,
                  "bytes_down":20,
                  "blocked":true,
                  "category":"ads_tracker",
                  "verdict":"BLOCKED",
                  "fingerprint":{"tls_ver":"1.3","alpn":"h2","ja3_lite":"abc"}
                }]
                """;

        OracleResult result = handler.handle(new OracleLoad(
                "job-1",
                "batch-1",
                1,
                "proxy.events",
                inline(payload),
                "",
                "",
                1
        ));

        assertEquals("success", result.status());
        assertEquals(1, result.rowCount());
        assertEquals("batch-1", sink.batchId);
        assertEquals(1, sink.proxyRows.size());
        assertEquals(1, sink.blockedRows.size());
        assertEquals(30L, sink.blockedRows.get(0).blockedBytes());
        assertFalse(result.checksum().isBlank());
    }

    @Test
    void handlesProxyPayloadAuditLoad(@TempDir Path outbox) {
        FakeSink sink = new FakeSink();
        OracleLoadHandler handler = handler(outbox, sink);
        String payload = """
                {
                  "observed_at":"2026-06-01T12:00:00Z",
                  "host":"api.example",
                  "method":"POST",
                  "path":"/login",
                  "content_type":"application/json",
                  "truncated":true,
                  "peer_ip":"10.0.0.2",
                  "body":{"password":"[REDACTED]"}
                }
                """;

        OracleResult result = handler.handle(new OracleLoad(
                "job-1",
                "batch-1",
                1,
                "proxy.payload_audit",
                inline(payload),
                "",
                "",
                1
        ));

        assertEquals("success", result.status());
        assertEquals(1, result.rowCount());
        assertEquals("batch-1", sink.batchId);
        assertEquals(1, sink.payloadAuditRows.size());
        ProxyPayloadAuditInsert row = sink.payloadAuditRows.getFirst();
        assertEquals("api.example", row.host());
        assertEquals("UP", row.direction());
        assertEquals("POST", row.httpMethod());
        assertEquals("/login", row.httpPath());
        assertEquals(1L, row.truncated());
    }

    @Test
    void returnsPermanentFailureForUnsupportedStream(@TempDir Path outbox) {
        OracleLoadHandler handler = handler(outbox, new FakeSink());

        OracleResult result = handler.handle(new OracleLoad(
                "job-1",
                "batch-1",
                1,
                "not.supported",
                inline("{\"ok\":true}"),
                "",
                "",
                1
        ));

        assertEquals("failed", result.status());
        assertEquals("permanent", result.errorClass());
        assertEquals(false, result.retryable());
    }

    @Test
    void returnsPermanentFailureForBlankPayloadRef(@TempDir Path outbox) {
        FakeSink sink = new FakeSink();
        DatabaseService databaseService = mock(DatabaseService.class);
        when(databaseService.repairBatchPayloadRef("batch-1")).thenReturn(new DbResult.Empty<>());
        OracleLoadHandler handler = handler(outbox, sink, databaseService);

        OracleResult result = handler.handle(new OracleLoad(
                "job-1",
                "batch-1",
                1,
                "proxy.events",
                "",
                "",
                "",
                1
        ));

        assertEquals("failed", result.status());
        assertEquals("permanent", result.errorClass());
        assertEquals("payload_ref must not be empty", result.errorText());
        assertNull(sink.batchId);
        verify(databaseService).repairBatchPayloadRef("batch-1");
    }

    @Test
    void repairsBlankPayloadRefBeforeLoading(@TempDir Path outbox) {
        FakeSink sink = new FakeSink();
        DatabaseService databaseService = mock(DatabaseService.class);
        String payload = """
                [{
                  "type":"connect",
                  "time":"2026-06-01T12:00:00Z",
                  "host":"tracker.example",
                  "blocked":false
                }]
                """;
        when(databaseService.repairBatchPayloadRef("batch-1")).thenReturn(new DbResult.Ok<>(inline(payload)));
        OracleLoadHandler handler = handler(outbox, sink, databaseService);

        OracleResult result = handler.handle(new OracleLoad(
                "job-1",
                "batch-1",
                1,
                "proxy.events",
                "",
                "",
                "",
                1
        ));

        assertEquals("success", result.status());
        assertEquals("batch-1", sink.batchId);
        assertEquals(1, sink.proxyRows.size());
        verify(databaseService).repairBatchPayloadRef("batch-1");
    }

    private OracleLoadHandler handler(Path outbox, OracleSink sink) {
        return handler(outbox, sink, mock(DatabaseService.class));
    }

    private OracleLoadHandler handler(Path outbox, OracleSink sink, DatabaseService databaseService) {
        return new OracleLoadHandler(
                new OraclePayloadResolver(outbox.toString(), objectMapper),
                new OracleTransformService(objectMapper),
                sink,
                new FixedClock(),
                databaseService
        );
    }

    private String inline(String payload) {
        return "inline://json/" + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }

    private static final class FixedClock extends OracleClock {
        @Override
        public String nowRfc3339() {
            return "2026-06-01T12:00:00Z";
        }
    }

    private static final class FakeSink implements OracleSink {
        private String batchId;
        private List<ProxyEventInsert> proxyRows = List.of();
        private List<BlockedEventInsert> blockedRows = List.of();
        private List<ProxyPayloadAuditInsert> payloadAuditRows = List.of();

        @Override
        public long insertProxyEvents(String batchId, List<ProxyEventInsert> rows, List<BlockedEventInsert> blockedRows) {
            this.batchId = batchId;
            this.proxyRows = rows;
            this.blockedRows = blockedRows;
            return rows.size();
        }

        @Override
        public long insertProxyPayloadAudit(String batchId, List<ProxyPayloadAuditInsert> rows) {
            this.batchId = batchId;
            this.payloadAuditRows = rows;
            return rows.size();
        }

        @Override
        public long insertWirelessAuditFrames(String batchId, List<WirelessAuditFrameInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessBandwidth(String batchId, List<WirelessBandwidthInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessRogueAp(String batchId, List<WirelessRogueApInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessDeauthFlood(String batchId, List<WirelessDeauthFloodInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessSignalAnomaly(String batchId, List<WirelessSignalAnomalyInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessPmfAttack(String batchId, List<WirelessPmfAttackInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessClientInventory(String batchId, List<WirelessClientInventoryInsert> rows) {
            return rows.size();
        }

        @Override
        public long insertWirelessProbeRequests(String batchId, List<WirelessProbeRequestInsert> rows) {
            return rows.size();
        }
    }
}
