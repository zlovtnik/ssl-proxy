package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.OracleSinkProperties;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Component
public class JdbcOracleSink implements OracleSink {

    private static final Logger log = LoggerFactory.getLogger(JdbcOracleSink.class);

    static final List<OracleObjectRequirement> CORE_SCHEMA_OBJECTS = List.of(
            OracleObjectRequirement.table("PROXY_EVENTS"),
            OracleObjectRequirement.table("PROXY_BLOCKED_HOST_ROLLUPS"),
            OracleObjectRequirement.table("PROXY_PAYLOAD_AUDIT")
    );

    static final List<OracleObjectRequirement> WIRELESS_SCHEMA_OBJECTS = List.of(
            OracleObjectRequirement.table("WIRELESS_SENSORS"),
            OracleObjectRequirement.table("WIRELESS_AUDIT_FRAMES"),
            OracleObjectRequirement.table("WIRELESS_BANDWIDTH_WINDOWS"),
            OracleObjectRequirement.table("WIRELESS_ALERTS"),
            OracleObjectRequirement.table("WIRELESS_ALERTS_LEDGER"),
            OracleObjectRequirement.table("WIRELESS_CLIENT_INVENTORY"),
            OracleObjectRequirement.table("WIRELESS_PROBE_REQUESTS"),
            OracleObjectRequirement.procedure("WIRELESS_UPSERT_SENSOR"),
            OracleObjectRequirement.procedure("WIRELESS_MERGE_BANDWIDTH_ALERTS")
    );

    static final List<OracleObjectRequirement> REQUIRED_SCHEMA_OBJECTS = java.util.stream.Stream
            .concat(CORE_SCHEMA_OBJECTS.stream(), WIRELESS_SCHEMA_OBJECTS.stream())
            .toList();

    private final OracleConnectionFactory connectionFactory;
    private final OracleSinkProperties props;
    private final ObjectMapper objectMapper;
    private final ObservationRegistry observationRegistry;

    public JdbcOracleSink(OracleConnectionFactory connectionFactory,
                          OracleSinkProperties props,
                          ObjectMapper objectMapper,
                          ObservationRegistry observationRegistry) {
        this.connectionFactory = connectionFactory;
        this.props = props;
        this.objectMapper = objectMapper;
        this.observationRegistry = observationRegistry;
    }

    @PostConstruct
    public void validateStartupSchema() {
        if (!props.enabled()) {
            return;
        }
        try (Connection connection = connectionFactory.getConnection()) {
            try {
                validateSchemaObjects(connection);
            } catch (IllegalStateException e) {
                if (props.schemaValidationWarnOnly()) {
                    log.warn("event=oracle_schema_preflight status=warn_only error=\"{}\"", sanitize(e.getMessage()));
                } else {
                    throw new BeanInitializationException("Oracle schema preflight failed", e);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Oracle sink schema preflight failed: " + sanitize(e.getMessage()), e);
        }
    }

    void validateSchemaObjects(Connection connection) throws SQLException {
        List<OracleObjectRequirement> required = props.validateWirelessObjects()
                ? REQUIRED_SCHEMA_OBJECTS
                : CORE_SCHEMA_OBJECTS;
        String placeholders = String.join(", ", Collections.nCopies(required.size(), "?"));
        String sql = """
                select object_name, object_type, status
                from all_objects
                where object_name in (%s)
                  and object_type in ('TABLE', 'PROCEDURE')
                """.formatted(placeholders);

        Map<OracleObjectRequirement, String> foundStatuses = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setQueryTimeout(props.statementTimeoutSecs());
            int index = 1;
            for (OracleObjectRequirement requirement : required) {
                statement.setString(index++, requirement.name());
            }
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    OracleObjectRequirement requirement = new OracleObjectRequirement(
                            resultSet.getString("OBJECT_NAME"),
                            resultSet.getString("OBJECT_TYPE")
                    );
                    foundStatuses.put(requirement, resultSet.getString("STATUS"));
                }
            }
        }

        List<String> missing = new ArrayList<>();
        List<String> invalid = new ArrayList<>();
        for (OracleObjectRequirement requirement : required) {
            String status = foundStatuses.get(requirement);
            if (status == null) {
                missing.add(requirement.displayName());
            } else if (!"VALID".equalsIgnoreCase(status)) {
                invalid.add(requirement.displayName() + " status=" + status);
            }
        }

        if (!missing.isEmpty() || !invalid.isEmpty()) {
            String details = "missing=[" + String.join(", ", missing) + "] invalid=[" + String.join(", ", invalid) + "]";
            throw new IllegalStateException("Oracle sink schema objects unavailable for user "
                    + props.requiredUser()
                    + ": "
                    + details
                    + "; apply sql/oracle.sql to the ORACLE_USER schema or grant visible synonyms for these objects");
        }
    }

    @Override
    public long insertProxyEvents(String batchId, List<ProxyEventInsert> rows, List<BlockedEventInsert> blockedRows)
            throws Exception {
        return observeOracle("oracle.insert_proxy_events", () -> {
            try {
                return withTransaction(connection -> insertProxyEventsTransaction(connection, batchId, rows, blockedRows));
            } catch (Exception e) {
                if (isProxyEventsBatchRowDuplicate(e.getMessage())) {
                    return observeOracle("oracle.insert_proxy_events_retry",
                            () -> withTransaction(connection -> insertProxyEventsTransaction(connection, batchId, rows, blockedRows)));
                }
                throw e;
            }
        });
    }

    @Override
    public long insertProxyPayloadAudit(String batchId, List<ProxyPayloadAuditInsert> rows) throws Exception {
        return observeOracle("oracle.insert_proxy_payload_audit", () -> {
            long inserted = withRetry("insert_proxy_payload_audit", 2, () -> withTransaction(connection -> {
                String sql = """
                        insert into PROXY_PAYLOAD_AUDIT (
                            CORRELATION_ID, HOST, DIRECTION, CAPTURED_AT, BYTE_OFFSET,
                            PAYLOAD_OBJECT_KEY, CONTENT_TYPE, HTTP_METHOD, HTTP_STATUS,
                            HTTP_PATH, IS_ENCRYPTED, TRUNCATED, PEER_IP, NOTES
                        ) values (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """;
                try (PreparedStatement statement = prepare(connection, sql)) {
                    long insertedRows = 0L;
                    for (ProxyPayloadAuditInsert row : rows) {
                        bindAll(statement, rawUuidBytes(row.correlationId()), row.host(), row.direction(), row.capturedAt(),
                                row.byteOffset(), row.payloadObjectKey(), row.contentType(), row.httpMethod(),
                                row.httpStatus(), row.httpPath(), row.isEncrypted(), row.truncated(),
                                row.peerIp(), row.notes());
                        try {
                            statement.executeUpdate();
                            insertedRows++;
                        } catch (SQLException e) {
                            if (!isProxyPayloadAuditDuplicate(e.getMessage())) {
                                throw e;
                            }
                        }
                    }
                    return insertedRows;
                }
            }));
            log.info("event=oracle_insert status=ok target=proxy_payload_audit batch_id={} rows={}",
                    batchId, inserted);
            return inserted;
        });
    }

    @Override
    public long insertWirelessAuditFrames(String batchId, List<WirelessAuditFrameInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_audit_frames", () -> {
            long inserted = withRetry("insert_wireless_audit_frames", 2, () -> withTransaction(connection -> {
                if (rows.isEmpty()) {
                    return 0L;
                }
                WirelessAuditFrameInsert first = rows.stream()
                        .min(java.util.Comparator.comparing(row -> row.observedAt()))
                        .orElseThrow();
                try (PreparedStatement statement = prepare(connection,
                        "BEGIN WIRELESS_UPSERT_SENSOR(?, ?, ?, ?, ?); END;")) {
                    bindAll(statement, first.sensorId(), first.locationId(), first.iface(), first.regDomain(), first.observedAt());
                    statement.execute();
                }
                String sql = """
                        merge into WIRELESS_AUDIT_FRAMES tgt
                        using (
                            select ? BATCH_ID, ? ROW_SEQUENCE, ? EVENT_TYPE, ? OBSERVED_AT,
                                   ? SENSOR_ID, ? LOCATION_ID, ? INTERFACE, ? CHANNEL,
                                   ? BAND, ? FRAME_TYPE, ? FRAME_SUBTYPE, ? BSSID, ? SOURCE_MAC,
                                   ? DESTINATION_MAC, ? TRANSMITTER_MAC, ? RECEIVER_MAC,
                                   ? DESTINATION_BSSID, ? SSID, ? SIGNAL_DBM,
                                   ? SEQUENCE_NUMBER, ? RAW_LEN, ? IS_RETRY,
                                   ? IS_MORE_DATA, ? IS_POWER_SAVE, ? IS_PROTECTED,
                                   ? IS_TO_DS, ? IS_FROM_DS, ? IS_HANDSHAKE,
                                   ? SECURITY_FLAGS, ? DEVICE_ID, ? USERNAME,
                                   ? IDENTITY_SOURCE, ? TAGS, ? ANOMALY_REASONS,
                                   ? RAW_JSON
                            from dual
                        ) src
                        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
                        when not matched then insert (
                            BATCH_ID, ROW_SEQUENCE, EVENT_TYPE, OBSERVED_AT, SENSOR_ID, LOCATION_ID,
                            INTERFACE, CHANNEL, BAND, FRAME_TYPE, FRAME_SUBTYPE, BSSID, SOURCE_MAC,
                            DESTINATION_MAC, TRANSMITTER_MAC, RECEIVER_MAC, DESTINATION_BSSID, SSID,
                            SIGNAL_DBM, SEQUENCE_NUMBER, RAW_LEN, IS_RETRY, IS_MORE_DATA,
                            IS_POWER_SAVE, IS_PROTECTED, IS_TO_DS, IS_FROM_DS, IS_HANDSHAKE,
                            SECURITY_FLAGS, DEVICE_ID, USERNAME, IDENTITY_SOURCE, TAGS,
                            ANOMALY_REASONS, RAW_JSON
                        ) values (
                            src.BATCH_ID, src.ROW_SEQUENCE, src.EVENT_TYPE, src.OBSERVED_AT,
                            src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL, src.BAND,
                            src.FRAME_TYPE, src.FRAME_SUBTYPE, src.BSSID, src.SOURCE_MAC,
                            src.DESTINATION_MAC, src.TRANSMITTER_MAC, src.RECEIVER_MAC,
                            src.DESTINATION_BSSID, src.SSID, src.SIGNAL_DBM, src.SEQUENCE_NUMBER,
                            src.RAW_LEN, src.IS_RETRY, src.IS_MORE_DATA, src.IS_POWER_SAVE,
                            src.IS_PROTECTED, src.IS_TO_DS, src.IS_FROM_DS, src.IS_HANDSHAKE,
                            src.SECURITY_FLAGS, src.DEVICE_ID, src.USERNAME, src.IDENTITY_SOURCE,
                            src.TAGS, src.ANOMALY_REASONS, src.RAW_JSON
                        )
                        """;
                try (PreparedStatement statement = prepare(connection, sql)) {
                    for (WirelessAuditFrameInsert row : rows) {
                        bindAll(statement, batchId, row.rowSequence(), row.eventType(), row.observedAt(),
                                row.sensorId(), row.locationId(), row.iface(), row.channel(),
                                wirelessBandForChannel(row.channel()), row.frameType(), row.frameSubtype(),
                                row.bssid(), row.sourceMac(), row.destinationMac(),
                                row.transmitterMac(), row.receiverMac(), row.destinationBssid(), row.ssid(),
                                row.signalDbm(), row.sequenceNumber(), row.rawLen(), row.isRetry(),
                                row.isMoreData(), row.isPowerSave(), row.isProtected(), row.isToDs(),
                                row.isFromDs(), row.isHandshake(), row.securityFlags(), row.deviceId(),
                                row.username(), row.identitySource(), row.tags(), row.anomalyReasons(), row.rawJson());
                        statement.executeUpdate();
                    }
                }
                return (long) rows.size();
            }));
            log.info("event=oracle_insert status=ok target=wireless_audit_frames batch_id={} rows={}",
                    batchId, inserted);
            return inserted;
        });
    }

    @Override
    public long insertWirelessBandwidth(String batchId, List<WirelessBandwidthInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_bandwidth", () -> {
            long inserted = withRetry("insert_wireless_bandwidth", 2, () -> withTransaction(connection -> {
                String sql = """
                        merge into WIRELESS_BANDWIDTH_WINDOWS tgt
                        using (
                            select ? BATCH_ID, ? ROW_SEQUENCE, ? SCHEMA_VERSION, ? WINDOW_START,
                                   ? WINDOW_END, ? SENSOR_ID, ? LOCATION_ID, ? INTERFACE,
                                   ? CHANNEL, ? BAND, ? SOURCE_MAC, ? DESTINATION_BSSID, ? SSID,
                                   ? BYTES, ? FRAME_COUNT, ? RETRY_COUNT, ? MORE_DATA_COUNT,
                                   ? POWER_SAVE_COUNT, ? STRONGEST_SIGNAL_DBM, ? HIST_UNDER_100,
                                   ? HIST_100_500, ? HIST_500_1000, ? HIST_1000_1500,
                                   ? INTER_ARRIVAL_P50_MS, ? EXTERNAL_BSSID, ? THRESHOLD_EXCEEDED,
                                   ? WALL_CLOCK_DELTA_MS, ? WINDOW_IS_PARTIAL, ? PUBLISHED_AT
                            from dual
                        ) src
                        on (tgt.BATCH_ID = src.BATCH_ID and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE)
                        when not matched then insert (
                            BATCH_ID, ROW_SEQUENCE, SCHEMA_VERSION, WINDOW_START, WINDOW_END,
                            SENSOR_ID, LOCATION_ID, INTERFACE, CHANNEL, BAND, SOURCE_MAC, DESTINATION_BSSID,
                            SSID, BYTES, FRAME_COUNT, RETRY_COUNT, MORE_DATA_COUNT, POWER_SAVE_COUNT,
                            STRONGEST_SIGNAL_DBM, HIST_UNDER_100, HIST_100_500, HIST_500_1000,
                            HIST_1000_1500, INTER_ARRIVAL_P50_MS, EXTERNAL_BSSID, THRESHOLD_EXCEEDED,
                            WALL_CLOCK_DELTA_MS, WINDOW_IS_PARTIAL, PUBLISHED_AT
                        ) values (
                            src.BATCH_ID, src.ROW_SEQUENCE, src.SCHEMA_VERSION, src.WINDOW_START,
                            src.WINDOW_END, src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL, src.BAND,
                            src.SOURCE_MAC, src.DESTINATION_BSSID, src.SSID, src.BYTES, src.FRAME_COUNT,
                            src.RETRY_COUNT, src.MORE_DATA_COUNT, src.POWER_SAVE_COUNT,
                            src.STRONGEST_SIGNAL_DBM, src.HIST_UNDER_100, src.HIST_100_500,
                            src.HIST_500_1000, src.HIST_1000_1500, src.INTER_ARRIVAL_P50_MS,
                            src.EXTERNAL_BSSID, src.THRESHOLD_EXCEEDED, src.WALL_CLOCK_DELTA_MS,
                            src.WINDOW_IS_PARTIAL, src.PUBLISHED_AT
                        )
                        """;
                try (PreparedStatement statement = prepare(connection, sql)) {
                    for (WirelessBandwidthInsert row : rows) {
                        bindAll(statement, batchId, row.rowSequence(), row.schemaVersion(), row.windowStart(),
                                row.windowEnd(), row.sensorId(), row.locationId(), row.iface(), row.channel(),
                                wirelessBandForChannel(row.channel()), row.sourceMac(), row.destinationBssid(),
                                row.ssid(), row.bytes(), row.frameCount(),
                                row.retryCount(), row.moreDataCount(), row.powerSaveCount(), row.strongestSignalDbm(),
                                row.histUnder100(), row.hist100500(), row.hist5001000(), row.hist10001500(),
                                row.interArrivalP50Ms(), row.externalBssid(), row.thresholdExceeded(),
                                row.wallClockDeltaMs(), row.windowIsPartial(), row.publishedAt());
                        statement.executeUpdate();
                    }
                }
                try (PreparedStatement statement = prepare(connection, "BEGIN WIRELESS_MERGE_BANDWIDTH_ALERTS(?); END;")) {
                    bindAll(statement, batchId);
                    statement.execute();
                }
                return (long) rows.size();
            }));
            log.info("event=oracle_insert status=ok target=wireless_bandwidth_windows batch_id={} rows={}",
                    batchId, inserted);
            return inserted;
        });
    }

    @Override
    public long insertWirelessRogueAp(String batchId, List<WirelessRogueApInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_rogue_ap",
                () -> withRetry("insert_wireless_rogue_ap", 2,
                        () -> mergeWirelessAlerts(batchId, rows, "rogue_ap", row -> new Object[]{
                                row.rowSequence(), row.detectedAt(), row.sensorId(), row.locationId(), row.iface(), row.channel(),
                                row.rogueBssid(), null, row.ssid(), row.signalDbm(),
                                jsonDetails("ssid_impersonation", row.ssidImpersonation()), row.rawJson()
                        })));
    }

    @Override
    public long insertWirelessDeauthFlood(String batchId, List<WirelessDeauthFloodInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_deauth_flood",
                () -> withRetry("insert_wireless_deauth_flood", 2,
                        () -> mergeWirelessAlerts(batchId, rows, "deauth_flood", row -> new Object[]{
                                row.rowSequence(), row.detectedAt(), row.sensorId(), row.locationId(), row.iface(), row.channel(),
                                row.attackerMac(), row.targetBssid(), row.targetSsid(), row.signalDbm(),
                                jsonDetails("deauth_count", row.deauthCount(), "window_secs", row.windowSecs(), "threshold", row.threshold()),
                                row.rawJson()
                        })));
    }

    @Override
    public long insertWirelessSignalAnomaly(String batchId, List<WirelessSignalAnomalyInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_signal_anomaly",
                () -> withRetry("insert_wireless_signal_anomaly", 2,
                        () -> mergeWirelessAlerts(batchId, rows, "signal_anomaly", row -> new Object[]{
                                row.rowSequence(), row.detectedAt(), row.sensorId(), row.locationId(), null, row.channel(),
                                row.sourceMac(), row.bssid(), row.ssid(), row.observedDbm(),
                                jsonDetails("baseline_dbm", row.baselineDbm(), "observed_dbm", row.observedDbm(),
                                        "dbm_delta", row.dbmDelta(), "configured_delta", row.configuredDelta()),
                                null
                        })));
    }

    @Override
    public long insertWirelessPmfAttack(String batchId, List<WirelessPmfAttackInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_pmf_attack",
                () -> withRetry("insert_wireless_pmf_attack", 2,
                        () -> mergeWirelessAlerts(batchId, rows, "pmf_attack", row -> new Object[]{
                                row.rowSequence(), row.detectedAt(), row.sensorId(), row.locationId(), null, row.channel(),
                                row.targetMac(), row.targetBssid(), row.ssid(), null,
                                jsonDetails("attack_tag", row.attackTag(), "reconnect_window_ms", row.reconnectWindowMs()),
                                null
                        })));
    }

    @Override
    public long insertWirelessClientInventory(String batchId, List<WirelessClientInventoryInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_client_inventory", () -> {
            long inserted = withRetry("insert_wireless_client_inventory", 2, () -> withTransaction(connection -> {
                String sql = """
                        merge into WIRELESS_CLIENT_INVENTORY tgt
                        using (
                            select ? SENSOR_ID, ? LOCATION_ID, ? SNAPSHOT_AT, ? CLIENT_MAC,
                                   ? BSSID, ? SSID, ? DEVICE_ID, ? USERNAME, ? IDENTITY_SOURCE,
                                   ? LAST_SEEN, ? FIRST_SEEN, ? SIGNAL_DBM, ? IS_AUTHORIZED
                            from dual
                        ) src
                        on (
                            tgt.SENSOR_ID = src.SENSOR_ID
                            and tgt.SNAPSHOT_AT = src.SNAPSHOT_AT
                            and tgt.CLIENT_MAC = src.CLIENT_MAC
                        )
                        when matched then update set
                            tgt.LOCATION_ID = src.LOCATION_ID,
                            tgt.BSSID = src.BSSID,
                            tgt.SSID = src.SSID,
                            tgt.DEVICE_ID = src.DEVICE_ID,
                            tgt.USERNAME = src.USERNAME,
                            tgt.IDENTITY_SOURCE = src.IDENTITY_SOURCE,
                            tgt.LAST_SEEN = src.LAST_SEEN,
                            tgt.FIRST_SEEN = src.FIRST_SEEN,
                            tgt.SIGNAL_DBM = src.SIGNAL_DBM,
                            tgt.IS_AUTHORIZED = src.IS_AUTHORIZED
                        when not matched then insert (
                            SENSOR_ID, LOCATION_ID, SNAPSHOT_AT, CLIENT_MAC, BSSID, SSID,
                            DEVICE_ID, USERNAME, IDENTITY_SOURCE, LAST_SEEN, FIRST_SEEN,
                            SIGNAL_DBM, IS_AUTHORIZED
                        ) values (
                            src.SENSOR_ID, src.LOCATION_ID, src.SNAPSHOT_AT, src.CLIENT_MAC,
                            src.BSSID, src.SSID, src.DEVICE_ID, src.USERNAME, src.IDENTITY_SOURCE,
                            src.LAST_SEEN, src.FIRST_SEEN, src.SIGNAL_DBM, src.IS_AUTHORIZED
                        )
                        """;
                try (PreparedStatement statement = prepare(connection, sql)) {
                    for (WirelessClientInventoryInsert row : rows) {
                        bindAll(statement, row.sensorId(), row.locationId(), row.snapshotAt(), row.clientMac(),
                                row.bssid(), row.ssid(), row.deviceId(), row.username(), row.identitySource(),
                                row.lastSeen(), row.firstSeen(), row.signalDbm(), row.isAuthorized());
                        statement.executeUpdate();
                    }
                }
                return (long) rows.size();
            }));
            log.info("event=oracle_insert status=ok target=wireless_client_inventory batch_id={} rows={}",
                    batchId, inserted);
            return inserted;
        });
    }

    @Override
    public long insertWirelessProbeRequests(String batchId, List<WirelessProbeRequestInsert> rows) throws Exception {
        return observeOracle("oracle.insert_wireless_probe_requests", () -> {
            long inserted = withRetry("insert_wireless_probe_requests", 2, () -> withTransaction(connection -> {
                String sql = """
                        merge into WIRELESS_PROBE_REQUESTS tgt
                        using (
                            select ? BATCH_ID, ? CLIENT_MAC, ? SSID, ? KNOWN_BSSID,
                                   ? FIRST_SEEN, ? LAST_SEEN, ? PROBE_COUNT
                            from dual
                        ) src
                        on (
                            tgt.BATCH_ID = src.BATCH_ID
                            and tgt.CLIENT_MAC = src.CLIENT_MAC
                            and (tgt.SSID = src.SSID or (tgt.SSID is null and src.SSID is null))
                        )
                        when matched then update set
                            tgt.KNOWN_BSSID = src.KNOWN_BSSID,
                            tgt.FIRST_SEEN = src.FIRST_SEEN,
                            tgt.LAST_SEEN = src.LAST_SEEN,
                            tgt.PROBE_COUNT = src.PROBE_COUNT
                        when not matched then insert (
                            BATCH_ID, CLIENT_MAC, SSID, KNOWN_BSSID, FIRST_SEEN, LAST_SEEN, PROBE_COUNT
                        ) values (
                            src.BATCH_ID, src.CLIENT_MAC, src.SSID, src.KNOWN_BSSID,
                            src.FIRST_SEEN, src.LAST_SEEN, src.PROBE_COUNT
                        )
                        """;
                try (PreparedStatement statement = prepare(connection, sql)) {
                    for (WirelessProbeRequestInsert row : rows) {
                        bindAll(statement, batchId, row.clientMac(), row.ssid(), row.knownBssid(),
                                row.firstSeen(), row.lastSeen(), row.probeCount());
                        statement.executeUpdate();
                    }
                }
                return (long) rows.size();
            }));
            log.info("event=oracle_insert status=ok target=wireless_probe_requests batch_id={} rows={}",
                    batchId, inserted);
            return inserted;
        });
    }

    private long insertProxyEventsTransaction(Connection connection,
                                              String batchId,
                                              List<ProxyEventInsert> rows,
                                              List<BlockedEventInsert> blockedRows) throws SQLException {
        Set<Long> inserted = new HashSet<>();
        String sql = """
                insert into proxy_events (
                    batch_id, row_sequence, event_time, event_timestamp_utc, event_type, host, peer_ip, wg_pubkey,
                    device_id, identity_source, peer_hostname, client_ua, bytes_up, bytes_down,
                    status_code, blocked, obfuscation_profile, correlation_id, parent_event_id,
                    event_sequence, duration_ms, reason, raw_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = prepare(connection, sql)) {
            for (int index = 0; index < rows.size(); index++) {
                long rowSequence = index + 1L;
                ProxyEventInsert row = rows.get(index);
                bindAll(statement, batchId, rowSequence, row.eventTime(), eventTimestampUtc(row.eventTime()),
                        row.eventType(), row.host(), row.peerIp(), row.wgPubkey(),
                        rawUuidBytes(row.deviceId()), normalizedIdentitySource(row.identitySource()),
                        row.peerHostname(), row.clientUa(), row.bytesUp(), row.bytesDown(), row.statusCode(),
                        row.blocked(), row.obfuscationProfile(), rawUuidBytes(row.correlationId()),
                        rawUuidBytes(row.parentEventId()), row.eventSequence(), row.durationMs(), row.reason(),
                        row.rawJson());
                try {
                    statement.executeUpdate();
                    inserted.add(rowSequence);
                } catch (SQLException e) {
                    if (!isProxyEventsBatchRowDuplicate(e.getMessage())) {
                        throw e;
                    }
                }
            }
        }
        upsertBlockedEvents(connection, blockedRows, inserted);
        return inserted.size();
    }

    private void upsertBlockedEvents(Connection connection,
                                     List<BlockedEventInsert> rows,
                                     Set<Long> insertedProxyRowSequences) throws SQLException {
        if (rows.isEmpty()) {
            return;
        }
        String sql = """
                merge into PROXY_BLOCKED_HOST_ROLLUPS be
                using (
                    select ? as host, ? as blocked_bytes, ? as frequency_hz, ? as risk_score,
                           ? as category, ? as verdict, ? as tarpit_held_ms, ? as iat_ms,
                           ? as consecutive_blocks, ? as last_verdict, ? as tls_ver, ? as alpn,
                           ? as ja3_lite, ? as resolved_ip, ? as asn_org
                    from dual
                ) src
                on (be.host = src.host)
                when matched then update set
                    be.blocked_attempts = be.blocked_attempts + 1,
                    be.blocked_bytes = be.blocked_bytes + nvl(src.blocked_bytes, 0),
                    be.frequency_hz = nvl(src.frequency_hz, be.frequency_hz),
                    be.verdict = nvl(src.verdict, be.verdict),
                    be.category = nvl(src.category, be.category),
                    be.risk_score = nvl(src.risk_score, (be.blocked_bytes + nvl(src.blocked_bytes, 0)) * nvl(src.frequency_hz, be.frequency_hz)),
                    be.tarpit_held_ms = be.tarpit_held_ms + nvl(src.tarpit_held_ms, 0),
                    be.iat_ms = nvl(src.iat_ms, be.iat_ms),
                    be.consecutive_blocks = nvl(src.consecutive_blocks, be.consecutive_blocks + 1),
                    be.last_verdict = nvl(src.last_verdict, nvl(src.verdict, be.last_verdict)),
                    be.tls_ver = nvl(src.tls_ver, be.tls_ver),
                    be.alpn = nvl(src.alpn, be.alpn),
                    be.ja3_lite = nvl(src.ja3_lite, be.ja3_lite),
                    be.resolved_ip = nvl(src.resolved_ip, be.resolved_ip),
                    be.asn_org = nvl(src.asn_org, be.asn_org),
                    be.updated_at = systimestamp
                when not matched then insert (
                    host, blocked_attempts, blocked_bytes, frequency_hz, verdict, category,
                    risk_score, tarpit_held_ms, iat_ms, consecutive_blocks, last_verdict,
                    tls_ver, alpn, ja3_lite, resolved_ip, asn_org, updated_at, first_seen
                ) values (
                    src.host, 1, nvl(src.blocked_bytes, 0), nvl(src.frequency_hz, 0),
                    nvl(src.verdict, 'BLOCKED'), nvl(src.category, 'unknown'),
                    nvl(src.risk_score, nvl(src.blocked_bytes, 0) * nvl(src.frequency_hz, 0)),
                    nvl(src.tarpit_held_ms, 0), src.iat_ms, nvl(src.consecutive_blocks, 1),
                    nvl(src.last_verdict, nvl(src.verdict, 'BLOCKED')), src.tls_ver,
                    src.alpn, src.ja3_lite, src.resolved_ip, src.asn_org, systimestamp, systimestamp
                )
                """;
        try (PreparedStatement statement = prepare(connection, sql)) {
            for (BlockedEventInsert row : rows) {
                if (!insertedProxyRowSequences.contains(row.rowSequence())) {
                    continue;
                }
                bindAll(statement, row.host(), row.blockedBytes(), row.frequencyHz(), row.riskScore(),
                        row.category(), row.verdict(), row.tarpitHeldMs(), row.iatMs(), row.consecutiveBlocks(),
                        row.lastVerdict(), row.tlsVer(), row.alpn(), row.ja3Lite(), row.resolvedIp(), row.asnOrg());
                statement.executeUpdate();
            }
        }
    }

    private <T> long mergeWirelessAlerts(String batchId, List<T> rows, String alertType, AlertBinder<T> binder)
            throws Exception {
        return withTransaction(connection -> {
            String sql = """
                    merge into WIRELESS_ALERTS tgt
                    using (
                        select ? ALERT_TYPE, ? BATCH_ID, ? ROW_SEQUENCE, ? DETECTED_AT,
                               ? SENSOR_ID, ? LOCATION_ID, ? INTERFACE, ? CHANNEL,
                               ? PRIMARY_MAC, ? SECONDARY_MAC, ? SSID, ? SIGNAL_DBM,
                               ? DETAILS_JSON, ? RAW_JSON
                        from dual
                    ) src
                    on (
                        tgt.ALERT_TYPE = src.ALERT_TYPE
                        and tgt.BATCH_ID = src.BATCH_ID
                        and tgt.ROW_SEQUENCE = src.ROW_SEQUENCE
                    )
                    when matched then update set
                        tgt.DETECTED_AT = src.DETECTED_AT,
                        tgt.SENSOR_ID = src.SENSOR_ID,
                        tgt.LOCATION_ID = src.LOCATION_ID,
                        tgt.INTERFACE = src.INTERFACE,
                        tgt.CHANNEL = src.CHANNEL,
                        tgt.PRIMARY_MAC = src.PRIMARY_MAC,
                        tgt.SECONDARY_MAC = src.SECONDARY_MAC,
                        tgt.SSID = src.SSID,
                        tgt.SIGNAL_DBM = src.SIGNAL_DBM,
                        tgt.DETAILS_JSON = src.DETAILS_JSON,
                        tgt.RAW_JSON = src.RAW_JSON,
                        tgt.UPDATED_AT = SYSTIMESTAMP
                    when not matched then insert (
                        ALERT_TYPE, BATCH_ID, ROW_SEQUENCE, DETECTED_AT, SENSOR_ID, LOCATION_ID,
                        INTERFACE, CHANNEL, PRIMARY_MAC, SECONDARY_MAC, SSID, SIGNAL_DBM,
                        DETAILS_JSON, RAW_JSON
                    ) values (
                        src.ALERT_TYPE, src.BATCH_ID, src.ROW_SEQUENCE, src.DETECTED_AT,
                        src.SENSOR_ID, src.LOCATION_ID, src.INTERFACE, src.CHANNEL,
                        src.PRIMARY_MAC, src.SECONDARY_MAC, src.SSID, src.SIGNAL_DBM,
                        src.DETAILS_JSON, src.RAW_JSON
                    )
                    """;
            try (PreparedStatement statement = prepare(connection, sql)) {
                for (T row : rows) {
                    Object[] values = binder.values(row);
                    bindAll(statement, alertType, batchId, values[0], values[1], values[2], values[3],
                            values[4], values[5], values[6], values[7], values[8], values[9], values[10], values[11]);
                    statement.executeUpdate();
                }
            }
            return (long) rows.size();
        });
    }

    private <T> T withTransaction(SqlWork<T> work) throws Exception {
        try (Connection connection = connectionFactory.getConnection()) {
            try {
                connection.setAutoCommit(false);
                T result = work.apply(connection);
                connection.commit();
                return result;
            } catch (Exception e) {
                rollbackQuietly(connection);
                throw e;
            }
        }
    }

    private <T> T observeOracle(String operation, CheckedWork<T> work) throws Exception {
        Observation observation = Observation
                .createNotStarted("db.client.operation", observationRegistry)
                .lowCardinalityKeyValue("db.system", "oracle")
                .lowCardinalityKeyValue("db.operation", operation)
                .lowCardinalityKeyValue("db.name", "oracle")
                .start();
        try (Observation.Scope ignored = observation.openScope()) {
            T result = work.apply();
            observation.stop();
            return result;
        } catch (Exception e) {
            observation.error(e);
            observation.stop();
            throw e;
        }
    }

    private <T> T withRetry(String operation, int maxAttempts, CheckedWork<T> work) throws Exception {
        Exception last = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return work.apply();
            } catch (Exception e) {
                last = e;
                if (OracleErrorClass.classify(e.getMessage()) == OracleErrorClass.PERMANENT) {
                    throw e;
                }
                if (attempt < maxAttempts) {
                    log.warn("event=oracle_retry status=retrying operation={} attempt={}/{} error=\"{}\"",
                            operation, attempt, maxAttempts, sanitize(e.getMessage()));
                    try {
                        Thread.sleep(200L * attempt);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw interrupted;
                    }
                }
            }
        }
        if (last != null) {
            throw last;
        }
        throw new IllegalStateException("retry loop ended without executing " + operation);
    }

    private PreparedStatement prepare(Connection connection, String sql) throws SQLException {
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.setQueryTimeout(props.statementTimeoutSecs());
        return statement;
    }

    private void bindAll(PreparedStatement statement, Object... values) throws SQLException {
        statement.clearParameters();
        for (int index = 0; index < values.length; index++) {
            Object value = values[index];
            if (value == null) {
                statement.setNull(index + 1, Types.NULL);
            } else if (value instanceof OffsetDateTime offsetDateTime) {
                statement.setObject(index + 1, offsetDateTime);
            } else if (value instanceof byte[] bytes) {
                statement.setBytes(index + 1, bytes);
            } else {
                statement.setObject(index + 1, value);
            }
        }
    }

    private void rollbackQuietly(Connection connection) {
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // Preserve the original database error.
        }
    }

    private boolean isProxyEventsBatchRowDuplicate(String message) {
        String normalized = message == null ? "" : message.toUpperCase();
        return normalized.contains("ORA-00001") && normalized.contains("PROXY_EVENTS_BATCH_ROW_IDX");
    }

    private boolean isProxyPayloadAuditDuplicate(String message) {
        String normalized = message == null ? "" : message.toUpperCase();
        return normalized.contains("ORA-00001") && normalized.contains("PROXY_PAYLOAD_AUDIT_UQ");
    }

    static LocalDateTime eventTimestampUtc(OffsetDateTime value) {
        return value.withOffsetSameInstant(ZoneOffset.UTC)
                .toLocalDateTime()
                .truncatedTo(ChronoUnit.MILLIS);
    }

    static String wirelessBandForChannel(long channel) {
        return channel >= 1 && channel <= 14 ? "2.4GHz" : "5GHz";
    }

    static byte[] rawUuidBytes(String value) throws SQLException {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.matches("[0-9a-fA-F]{32}")) {
            normalized = normalized.substring(0, 8)
                    + "-"
                    + normalized.substring(8, 12)
                    + "-"
                    + normalized.substring(12, 16)
                    + "-"
                    + normalized.substring(16, 20)
                    + "-"
                    + normalized.substring(20);
        }
        try {
            UUID uuid = UUID.fromString(normalized);
            ByteBuffer buffer = ByteBuffer.allocate(16);
            buffer.putLong(uuid.getMostSignificantBits());
            buffer.putLong(uuid.getLeastSignificantBits());
            return buffer.array();
        } catch (IllegalArgumentException e) {
            throw new SQLException("invalid UUID value for RAW(16)", e);
        }
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }

    private String normalizedIdentitySource(String identitySource) {
        return identitySource == null || identitySource.isBlank() ? "unknown" : identitySource;
    }

    private String jsonDetails(Object... keyValues) {
        var node = objectMapper.createObjectNode();
        for (int index = 0; index + 1 < keyValues.length; index += 2) {
            Object value = keyValues[index + 1];
            String key = String.valueOf(keyValues[index]);
            if (value == null) {
                node.putNull(key);
            } else if (value instanceof Number number) {
                node.putPOJO(key, number);
            } else if (value instanceof Boolean bool) {
                node.put(key, bool);
            } else {
                node.put(key, String.valueOf(value));
            }
        }
        try {
            return objectMapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("encode wireless alert details: " + e.getMessage(), e);
        }
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T apply(Connection connection) throws Exception;
    }

    @FunctionalInterface
    private interface CheckedWork<T> {
        T apply() throws Exception;
    }

    @FunctionalInterface
    private interface AlertBinder<T> {
        Object[] values(T row);
    }

    record OracleObjectRequirement(String name, String type) {
        OracleObjectRequirement {
            name = name.toUpperCase(Locale.ROOT);
            type = type.toUpperCase(Locale.ROOT);
        }

        static OracleObjectRequirement table(String name) {
            return new OracleObjectRequirement(name, "TABLE");
        }

        static OracleObjectRequirement procedure(String name) {
            return new OracleObjectRequirement(name, "PROCEDURE");
        }

        String displayName() {
            return type + " " + name;
        }
    }
}
