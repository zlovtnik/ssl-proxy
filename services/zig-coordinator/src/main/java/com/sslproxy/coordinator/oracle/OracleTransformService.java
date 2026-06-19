package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static com.sslproxy.coordinator.oracle.JsonFields.boolFlag;
import static com.sslproxy.coordinator.oracle.JsonFields.jsonArrayString;
import static com.sslproxy.coordinator.oracle.JsonFields.longAlias;
import static com.sslproxy.coordinator.oracle.JsonFields.nestedDouble;
import static com.sslproxy.coordinator.oracle.JsonFields.nestedLong;
import static com.sslproxy.coordinator.oracle.JsonFields.optionalDouble;
import static com.sslproxy.coordinator.oracle.JsonFields.optionalLong;
import static com.sslproxy.coordinator.oracle.JsonFields.optionalString;
import static com.sslproxy.coordinator.oracle.JsonFields.optionalTimestamp;
import static com.sslproxy.coordinator.oracle.JsonFields.rawJson;
import static com.sslproxy.coordinator.oracle.JsonFields.requiredLong;
import static com.sslproxy.coordinator.oracle.JsonFields.requiredString;
import static com.sslproxy.coordinator.oracle.JsonFields.requiredTimestamp;
import static com.sslproxy.coordinator.oracle.JsonFields.rowSequence;
import static com.sslproxy.coordinator.oracle.JsonFields.stringAlias;
import static com.sslproxy.coordinator.oracle.JsonFields.timestampAlias;

@Component
public class OracleTransformService {

    private final ObjectMapper objectMapper;

    public OracleTransformService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    OracleRowSet transform(OracleSinkTarget target, List<JsonNode> rows) {
        return switch (target) {
            case PROXY_EVENTS -> transformProxyRows(rows);
            case PROXY_PAYLOAD_AUDIT -> new OracleRowSet(
                    List.of(), List.of(), transformProxyPayloadAudit(rows), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
            case WIRELESS_AUDIT_FRAMES -> new OracleRowSet(
                    List.of(), List.of(), List.of(), transformWirelessAudit(rows), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
            case WIRELESS_BANDWIDTH -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), transformWirelessBandwidth(rows),
                    List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
            case WIRELESS_ROGUE_AP -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    transformRogueAp(rows), List.of(), List.of(), List.of(), List.of(), List.of());
            case WIRELESS_DEAUTH_FLOOD -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), transformDeauthFlood(rows), List.of(), List.of(), List.of(), List.of());
            case WIRELESS_SIGNAL_ANOMALY -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), transformSignalAnomaly(rows), List.of(), List.of(), List.of());
            case WIRELESS_PMF_ATTACK -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), transformPmfAttack(rows), List.of(), List.of());
            case WIRELESS_CLIENT_INVENTORY -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), transformClientInventory(rows), List.of());
            case WIRELESS_PROBE_REQUESTS -> new OracleRowSet(
                    List.of(), List.of(), List.of(), List.of(), List.of(),
                    List.of(), List.of(), List.of(), List.of(), List.of(), transformProbeRequests(rows));
        };
    }

    private OracleRowSet transformProxyRows(List<JsonNode> rows) {
        List<ProxyEventInsert> proxyRows = new ArrayList<>(rows.size());
        List<BlockedEventInsert> blockedRows = new ArrayList<>();
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            ProxyEventInsert proxyRow = proxyEvent(row);
            proxyRows.add(proxyRow);
            blockedEvent(index, row, proxyRow).ifPresent(blockedRows::add);
        }
        return new OracleRowSet(
                List.copyOf(proxyRows), List.copyOf(blockedRows), List.of(), List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private ProxyEventInsert proxyEvent(JsonNode row) {
        String eventType = requiredString(row, "type", "proxy.events");
        String host = requiredString(row, "host", "proxy.events");
        return new ProxyEventInsert(
                requiredTimestamp(row, "time", "proxy.events"),
                eventType,
                host,
                optionalString(row, "peer_ip").orElse(null),
                optionalString(row, "wg_pubkey").orElse(null),
                optionalString(row, "device_id").orElse(null),
                optionalString(row, "identity_source").orElse(null),
                optionalString(row, "peer_hostname").orElse(null),
                optionalString(row, "client_ua").orElse(null),
                optionalLong(row, "bytes_up").orElse(0L),
                optionalLong(row, "bytes_down").orElse(0L),
                optionalLong(row, "status_code").orElse(null),
                boolFlag(row, "blocked"),
                optionalString(row, "obfuscation_profile").orElse(null),
                optionalString(row, "correlation_id").orElse(null),
                optionalString(row, "parent_event_id").orElse(null),
                optionalLong(row, "event_sequence").orElse(null),
                optionalLong(row, "duration_ms").orElse(null),
                optionalString(row, "reason").orElse(null),
                rawJson(objectMapper, row, "proxy row")
        );
    }

    private List<ProxyPayloadAuditInsert> transformProxyPayloadAudit(List<JsonNode> rows) {
        List<ProxyPayloadAuditInsert> inserts = new ArrayList<>(rows.size());
        for (JsonNode row : rows) {
            String raw = rawJson(objectMapper, row, "proxy.payload_audit row");
            inserts.add(new ProxyPayloadAuditInsert(
                    optionalString(row, "correlation_id").orElse(stableCorrelationId(raw)),
                    requiredString(row, "host", "proxy.payload_audit"),
                    optionalString(row, "direction").orElse("UP").toUpperCase(Locale.ROOT),
                    requiredTimestamp(row, "observed_at", "proxy.payload_audit"),
                    optionalLong(row, "byte_offset").orElse(0L),
                    optionalString(row, "payload_object_key").orElse(null),
                    optionalString(row, "content_type").orElse(null),
                    optionalString(row, "method").orElse(null),
                    optionalLong(row, "http_status").or(() -> optionalLong(row, "status_code")).orElse(null),
                    optionalString(row, "path").orElse(null),
                    boolFlag(row, "is_encrypted"),
                    boolFlag(row, "truncated"),
                    optionalString(row, "peer_ip").orElse(null),
                    optionalString(row, "notes").orElse(null)
            ));
        }
        return List.copyOf(inserts);
    }

    private java.util.Optional<BlockedEventInsert> blockedEvent(int index, JsonNode row, ProxyEventInsert proxyRow) {
        if (boolFlag(row, "blocked") == 0L) {
            return java.util.Optional.empty();
        }

        long blockedBytes = optionalLong(row, "blocked_bytes")
                .or(() -> nestedLong(row, "metrics", "blocked_bytes"))
                .or(() -> nestedLong(row, "metrics", "total_blocked_bytes_approx"))
                .orElse(Math.addExact(proxyRow.bytesUp(), proxyRow.bytesDown()));
        String verdict = optionalString(row, "verdict").orElse("BLOCKED");
        JsonNode fingerprint = row.get("fingerprint");
        return java.util.Optional.of(new BlockedEventInsert(
                rowSequence(index, "proxy blocked rollup"),
                proxyRow.host(),
                blockedBytes,
                optionalDouble(row, "frequency_hz").or(() -> nestedDouble(row, "metrics", "frequency_hz")).orElse(null),
                optionalDouble(row, "risk_score").or(() -> nestedDouble(row, "metrics", "risk_score")).orElse(null),
                optionalString(row, "category").orElse("unknown"),
                verdict,
                optionalLong(row, "tarpit_held_ms").orElse(0L),
                optionalLong(row, "iat_ms").or(() -> nestedLong(row, "metrics", "iat_ms")).orElse(null),
                optionalLong(row, "consecutive_blocks")
                        .or(() -> nestedLong(row, "metrics", "consecutive_blocks"))
                        .or(() -> optionalLong(row, "attempt_count"))
                        .or(() -> nestedLong(row, "metrics", "attempt_count"))
                        .orElse(null),
                verdict,
                nestedString(fingerprint, "tls_ver"),
                nestedString(fingerprint, "alpn"),
                nestedString(fingerprint, "ja3_lite"),
                optionalString(row, "resolved_ip").orElse(null),
                optionalString(row, "asn_org").orElse(null)
        ));
    }

    private List<WirelessAuditFrameInsert> transformWirelessAudit(List<JsonNode> rows) {
        List<WirelessAuditFrameInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            inserts.add(new WirelessAuditFrameInsert(
                    rowSequence(index, "wireless.audit"),
                    requiredString(row, "event_type", "wireless.audit"),
                    requiredTimestamp(row, "observed_at", "wireless.audit"),
                    requiredString(row, "sensor_id", "wireless.audit"),
                    requiredString(row, "location_id", "wireless.audit"),
                    requiredString(row, "interface", "wireless.audit"),
                    requiredLong(row, "channel", "wireless.audit"),
                    optionalString(row, "frame_type").orElse(null),
                    requiredString(row, "frame_subtype", "wireless.audit"),
                    optionalString(row, "bssid").orElse(null),
                    optionalString(row, "source_mac").orElse(null),
                    optionalString(row, "destination_mac").orElse(null),
                    optionalString(row, "transmitter_mac").orElse(null),
                    optionalString(row, "receiver_mac").orElse(null),
                    optionalString(row, "destination_bssid").orElse(null),
                    optionalString(row, "ssid").orElse(null),
                    optionalLong(row, "signal_dbm").orElse(null),
                    optionalLong(row, "sequence_number").orElse(null),
                    requiredLong(row, "raw_len", "wireless.audit"),
                    boolFlag(row, "retry"),
                    boolFlag(row, "more_data"),
                    boolFlag(row, "power_save"),
                    boolFlag(row, "protected"),
                    boolFlag(row, "to_ds"),
                    boolFlag(row, "from_ds"),
                    boolFlag(row, "handshake_captured"),
                    optionalLong(row, "security_flags").orElse(0L),
                    optionalString(row, "device_id").orElse(null),
                    optionalString(row, "username").orElse(null),
                    optionalString(row, "identity_source").orElse("unknown"),
                    jsonArrayString(objectMapper, row, "tags"),
                    jsonArrayString(objectMapper, row, "anomaly_reasons"),
                    rawJson(objectMapper, row, "wireless.audit row"),
                    optionalString(row, "reg_domain").orElse(null)
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessBandwidthInsert> transformWirelessBandwidth(List<JsonNode> rows) {
        List<WirelessBandwidthInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            inserts.add(new WirelessBandwidthInsert(
                    rowSequence(index, "audit.wireless.bandwidth"),
                    optionalLong(row, "schema_version").orElse(1L),
                    requiredTimestamp(row, "window_start", "audit.wireless.bandwidth"),
                    requiredTimestamp(row, "window_end", "audit.wireless.bandwidth"),
                    requiredString(row, "sensor_id", "audit.wireless.bandwidth"),
                    requiredString(row, "location_id", "audit.wireless.bandwidth"),
                    requiredString(row, "interface", "audit.wireless.bandwidth"),
                    requiredLong(row, "channel", "audit.wireless.bandwidth"),
                    requiredString(row, "source_mac", "audit.wireless.bandwidth"),
                    requiredString(row, "destination_bssid", "audit.wireless.bandwidth"),
                    optionalString(row, "ssid").orElse(null),
                    requiredLong(row, "bytes", "audit.wireless.bandwidth"),
                    requiredLong(row, "frame_count", "audit.wireless.bandwidth"),
                    optionalLong(row, "retry_count").orElse(0L),
                    optionalLong(row, "more_data_count").orElse(0L),
                    optionalLong(row, "power_save_count").orElse(0L),
                    optionalLong(row, "strongest_signal_dbm").orElse(null),
                    nestedLong(row, "frame_size_histogram", "under_100").orElse(0L),
                    nestedLong(row, "frame_size_histogram", "range_100_500").orElse(0L),
                    nestedLong(row, "frame_size_histogram", "range_500_1000").orElse(0L),
                    nestedLong(row, "frame_size_histogram", "range_1000_1500").orElse(0L),
                    optionalLong(row, "inter_arrival_p50_ms").orElse(null),
                    boolFlag(row, "external_bssid"),
                    boolFlag(row, "threshold_exceeded"),
                    optionalLong(row, "wall_clock_delta_ms").orElse(null),
                    boolFlag(row, "window_is_partial"),
                    optionalTimestamp(row, "published_at").orElse(null)
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessRogueApInsert> transformRogueAp(List<JsonNode> rows) {
        List<WirelessRogueApInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            long ssidImpersonation = boolFlag(row, "ssid_impersonation") | reasonFlag(row, "ssid_impersonation", "bssid_spoofing");
            inserts.add(new WirelessRogueApInsert(
                    rowSequence(index, "wireless.alert.rogue_ap"),
                    timestampAlias(row, "detected_at", "observed_at", "wireless.alert.rogue_ap"),
                    requiredString(row, "sensor_id", "wireless.alert.rogue_ap"),
                    requiredString(row, "location_id", "wireless.alert.rogue_ap"),
                    requiredString(row, "interface", "wireless.alert.rogue_ap"),
                    requiredLong(row, "channel", "wireless.alert.rogue_ap"),
                    stringAlias(row, "rogue_bssid", "bssid", "wireless.alert.rogue_ap"),
                    optionalString(row, "ssid").orElse(null),
                    optionalLong(row, "signal_dbm").orElse(null),
                    ssidImpersonation,
                    rawJson(objectMapper, row, "wireless rogue AP row")
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessDeauthFloodInsert> transformDeauthFlood(List<JsonNode> rows) {
        List<WirelessDeauthFloodInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            inserts.add(new WirelessDeauthFloodInsert(
                    rowSequence(index, "wireless.alert.deauth_flood"),
                    timestampAlias(row, "detected_at", "observed_at", "wireless.alert.deauth_flood"),
                    requiredString(row, "sensor_id", "wireless.alert.deauth_flood"),
                    requiredString(row, "location_id", "wireless.alert.deauth_flood"),
                    requiredString(row, "interface", "wireless.alert.deauth_flood"),
                    optionalLong(row, "channel").orElse(0L),
                    optionalString(row, "attacker_mac").or(() -> optionalString(row, "source_mac")).orElse(null),
                    optionalString(row, "target_bssid").or(() -> optionalString(row, "bssid")).orElse(null),
                    optionalString(row, "target_ssid").or(() -> optionalString(row, "ssid")).orElse(null),
                    longAlias(row, "deauth_count", "frame_count", "wireless.alert.deauth_flood"),
                    requiredLong(row, "window_secs", "wireless.alert.deauth_flood"),
                    optionalLong(row, "threshold").orElse(0L),
                    optionalLong(row, "signal_dbm").orElse(null),
                    rawJson(objectMapper, row, "wireless deauth flood row")
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessSignalAnomalyInsert> transformSignalAnomaly(List<JsonNode> rows) {
        List<WirelessSignalAnomalyInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            inserts.add(new WirelessSignalAnomalyInsert(
                    rowSequence(index, "wireless.alert.signal_anomaly"),
                    timestampAlias(row, "detected_at", "observed_at", "wireless.alert.signal_anomaly"),
                    requiredString(row, "sensor_id", "wireless.alert.signal_anomaly"),
                    requiredString(row, "location_id", "wireless.alert.signal_anomaly"),
                    requiredString(row, "source_mac", "wireless.alert.signal_anomaly"),
                    optionalString(row, "bssid").orElse(null),
                    optionalString(row, "ssid").orElse(null),
                    requiredLong(row, "channel", "wireless.alert.signal_anomaly"),
                    requiredLong(row, "baseline_dbm", "wireless.alert.signal_anomaly"),
                    requiredLong(row, "observed_dbm", "wireless.alert.signal_anomaly"),
                    Math.abs(requiredLong(row, "dbm_delta", "wireless.alert.signal_anomaly")),
                    requiredLong(row, "configured_delta", "wireless.alert.signal_anomaly")
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessPmfAttackInsert> transformPmfAttack(List<JsonNode> rows) {
        List<WirelessPmfAttackInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            inserts.add(new WirelessPmfAttackInsert(
                    rowSequence(index, "wireless.alert.pmf_attack"),
                    timestampAlias(row, "detected_at", "observed_at", "wireless.alert.pmf_attack"),
                    requiredString(row, "sensor_id", "wireless.alert.pmf_attack"),
                    requiredString(row, "location_id", "wireless.alert.pmf_attack"),
                    stringAlias(row, "target_mac", "source_mac", "wireless.alert.pmf_attack"),
                    optionalString(row, "target_bssid").or(() -> optionalString(row, "bssid")).orElse(null),
                    optionalString(row, "ssid").orElse(null),
                    optionalLong(row, "channel").orElse(null),
                    requiredString(row, "attack_tag", "wireless.alert.pmf_attack"),
                    optionalLong(row, "reconnect_window_ms").orElse(null)
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessClientInventoryInsert> transformClientInventory(List<JsonNode> rows) {
        List<WirelessClientInventoryInsert> inserts = new ArrayList<>(rows.size());
        for (JsonNode row : rows) {
            inserts.add(new WirelessClientInventoryInsert(
                    requiredString(row, "sensor_id", "wireless.client.inventory"),
                    requiredString(row, "location_id", "wireless.client.inventory"),
                    requiredTimestamp(row, "snapshot_at", "wireless.client.inventory"),
                    stringAlias(row, "client_mac", "source_mac", "wireless.client.inventory"),
                    optionalString(row, "bssid").orElse(null),
                    optionalString(row, "ssid").orElse(null),
                    optionalString(row, "device_id").orElse(null),
                    optionalString(row, "username").orElse(null),
                    optionalString(row, "identity_source").orElse(null),
                    requiredTimestamp(row, "last_seen", "wireless.client.inventory"),
                    requiredTimestamp(row, "first_seen", "wireless.client.inventory"),
                    optionalLong(row, "signal_dbm").or(() -> optionalLong(row, "last_signal_dbm")).orElse(null),
                    boolFlag(row, "is_authorized")
            ));
        }
        return List.copyOf(inserts);
    }

    private List<WirelessProbeRequestInsert> transformProbeRequests(List<JsonNode> rows) {
        List<WirelessProbeRequestInsert> inserts = new ArrayList<>(rows.size());
        for (int index = 0; index < rows.size(); index++) {
            JsonNode row = rows.get(index);
            inserts.add(new WirelessProbeRequestInsert(
                    rowSequence(index, "wireless.probe.flush"),
                    requiredString(row, "client_mac", "wireless.probe.flush"),
                    requiredString(row, "ssid", "wireless.probe.flush"),
                    optionalString(row, "known_bssid").orElse(null),
                    requiredTimestamp(row, "first_seen", "wireless.probe.flush"),
                    requiredTimestamp(row, "last_seen", "wireless.probe.flush"),
                    requiredLong(row, "probe_count", "wireless.probe.flush")
            ));
        }
        return List.copyOf(inserts);
    }

    private String nestedString(JsonNode parent, String field) {
        if (parent == null || parent.isNull()) {
            return null;
        }
        return optionalString(parent, field).orElse(null);
    }

    private long reasonFlag(JsonNode row, String first, String second) {
        JsonNode reasons = row.get("reasons");
        if (reasons == null || !reasons.isArray()) {
            return 0L;
        }
        for (JsonNode reason : reasons) {
            if (reason.isTextual() && (first.equals(reason.asText()) || second.equals(reason.asText()))) {
                return 1L;
            }
        }
        return 0L;
    }

    private String stableCorrelationId(String rawJson) {
        return UUID.nameUUIDFromBytes(rawJson.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
