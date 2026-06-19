package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.service.DatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class OracleLoadHandler {

    private static final Logger log = LoggerFactory.getLogger(OracleLoadHandler.class);

    private final OraclePayloadResolver payloadResolver;
    private final OracleTransformService transformService;
    private final OracleSink sink;
    private final OracleClock clock;
    private final DatabaseService databaseService;

    public OracleLoadHandler(OraclePayloadResolver payloadResolver,
                             OracleTransformService transformService,
                             OracleSink sink,
                             OracleClock clock,
                             DatabaseService databaseService) {
        this.payloadResolver = payloadResolver;
        this.transformService = transformService;
        this.sink = sink;
        this.clock = clock;
        this.databaseService = databaseService;
    }

    public OracleResult handle(OracleLoad load) {
        try {
            OracleLoad resolvedLoad = repairPayloadRefIfNeeded(load);
            validateLoad(resolvedLoad);
            OracleSinkTarget target = OracleSinkTarget.fromStreamName(resolvedLoad.streamName())
                    .orElseThrow(() -> new IllegalArgumentException("unsupported stream_name " + resolvedLoad.streamName()));
            String payload = payloadResolver.resolvePayload(resolvedLoad.payloadRef());
            List<JsonNode> values = payloadResolver.payloadRows(target, payload);
            OracleRowSet rows = transformService.transform(target, values);

            log.info("event=oracle_load status=validated batch_id={} stream_name={} target={} row_count={}",
                    resolvedLoad.batchId(), resolvedLoad.streamName(), target.checksumTag(), rows.inputRowCount(target));

            long rowCount = insert(resolvedLoad.batchId(), target, rows);
            if (rowCount > Integer.MAX_VALUE) {
                return OracleResult.failure(resolvedLoad.jobId(), resolvedLoad.batchId(), OracleErrorClass.PERMANENT,
                        "inserted row count exceeds i32 limit", clock.nowRfc3339());
            }
            return OracleResult.success(
                    resolvedLoad.jobId(),
                    resolvedLoad.batchId(),
                    (int) rowCount,
                    OracleChecksum.checksum(target, payload),
                    clock.nowRfc3339()
            );
        } catch (Exception e) {
            OracleErrorClass errorClass = e instanceof IllegalArgumentException
                    || e instanceof JsonProcessingException
                    ? OracleErrorClass.PERMANENT
                    : OracleErrorClass.classify(e.getMessage());
            log.error("event=oracle_load status=failed batch_id={} stream_name={} error_class={} error=\"{}\"",
                    load.batchId(), load.streamName(), errorClass.wireValue(), sanitize(e.getMessage()));
            return OracleResult.failure(load.jobId(), load.batchId(), errorClass, e.getMessage(), clock.nowRfc3339());
        }
    }

    private OracleLoad repairPayloadRefIfNeeded(OracleLoad load) {
        validateLoadMetadata(load);
        if (!load.payloadRef().isBlank()) {
            return load;
        }

        return switch (databaseService.repairBatchPayloadRef(load.batchId())) {
            case DbResult.Ok<String> ok when ok.value() != null && !ok.value().isBlank() -> {
                log.warn("event=oracle_load status=payload_ref_repaired batch_id={} stream_name={}",
                        load.batchId(), load.streamName());
                yield new OracleLoad(
                        load.jobId(),
                        load.batchId(),
                        load.batchNo(),
                        load.streamName(),
                        ok.value(),
                        load.cursorStart(),
                        load.cursorEnd(),
                        load.attempt()
                );
            }
            case DbResult.Empty<String> ignored -> load;
            case DbResult.Ok<String> ignored -> load;
            case DbResult.Err<String> err -> {
                log.warn("event=oracle_load status=payload_ref_repair_failed batch_id={} operation={} error=\"{}\"",
                        load.batchId(), err.operation(), sanitize(err.cause().getMessage()));
                yield load;
            }
        };
    }

    private void validateLoad(OracleLoad load) {
        validateLoadMetadata(load);
        if (load.payloadRef().isBlank()) {
            throw new IllegalArgumentException("payload_ref must not be empty");
        }
    }

    private void validateLoadMetadata(OracleLoad load) {
        if (load.jobId().isBlank()) {
            throw new IllegalArgumentException("job_id must not be empty");
        }
        if (load.batchId().isBlank()) {
            throw new IllegalArgumentException("batch_id must not be empty");
        }
        if (load.streamName().isBlank()) {
            throw new IllegalArgumentException("stream_name must not be empty");
        }
    }

    private long insert(String batchId, OracleSinkTarget target, OracleRowSet rows) throws Exception {
        return switch (target) {
            case PROXY_EVENTS -> sink.insertProxyEvents(batchId, rows.proxyEvents(), rows.blockedEvents());
            case PROXY_PAYLOAD_AUDIT -> sink.insertProxyPayloadAudit(batchId, rows.proxyPayloadAudit());
            case WIRELESS_AUDIT_FRAMES -> sink.insertWirelessAuditFrames(batchId, rows.wirelessAuditFrames());
            case WIRELESS_BANDWIDTH -> sink.insertWirelessBandwidth(batchId, rows.wirelessBandwidth());
            case WIRELESS_ROGUE_AP -> sink.insertWirelessRogueAp(batchId, rows.wirelessRogueAp());
            case WIRELESS_DEAUTH_FLOOD -> sink.insertWirelessDeauthFlood(batchId, rows.wirelessDeauthFlood());
            case WIRELESS_SIGNAL_ANOMALY -> sink.insertWirelessSignalAnomaly(batchId, rows.wirelessSignalAnomaly());
            case WIRELESS_PMF_ATTACK -> sink.insertWirelessPmfAttack(batchId, rows.wirelessPmfAttack());
            case WIRELESS_CLIENT_INVENTORY -> sink.insertWirelessClientInventory(batchId, rows.wirelessClientInventory());
            case WIRELESS_PROBE_REQUESTS -> sink.insertWirelessProbeRequests(batchId, rows.wirelessProbeRequests());
        };
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
