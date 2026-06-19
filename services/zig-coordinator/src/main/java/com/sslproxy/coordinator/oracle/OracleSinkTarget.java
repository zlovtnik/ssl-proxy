package com.sslproxy.coordinator.oracle;

import java.util.Optional;

public enum OracleSinkTarget {
    PROXY_EVENTS("proxy.events"),
    PROXY_PAYLOAD_AUDIT("proxy.payload_audit"),
    WIRELESS_AUDIT_FRAMES("wireless.audit"),
    WIRELESS_BANDWIDTH("audit.wireless.bandwidth"),
    WIRELESS_ROGUE_AP("wireless.alert.rogue_ap"),
    WIRELESS_DEAUTH_FLOOD("wireless.alert.deauth_flood"),
    WIRELESS_SIGNAL_ANOMALY("wireless.alert.signal_anomaly"),
    WIRELESS_PMF_ATTACK("wireless.alert.pmf_attack"),
    WIRELESS_CLIENT_INVENTORY("wireless.client.inventory"),
    WIRELESS_PROBE_REQUESTS("wireless.probe.flush");

    private final String checksumTag;

    OracleSinkTarget(String checksumTag) {
        this.checksumTag = checksumTag;
    }

    public String checksumTag() {
        return checksumTag;
    }

    public static Optional<OracleSinkTarget> fromStreamName(String streamName) {
        return switch (streamName == null ? "" : streamName) {
            case "proxy.events" -> Optional.of(PROXY_EVENTS);
            case "proxy.payload_audit" -> Optional.of(PROXY_PAYLOAD_AUDIT);
            case "wireless.audit" -> Optional.of(WIRELESS_AUDIT_FRAMES);
            case "audit.wireless.bandwidth" -> Optional.of(WIRELESS_BANDWIDTH);
            case "wireless.rogue_ap", "wireless.alert.rogue_ap" -> Optional.of(WIRELESS_ROGUE_AP);
            case "wireless.deauth_flood", "wireless.alert.deauth_flood" -> Optional.of(WIRELESS_DEAUTH_FLOOD);
            case "wireless.signal_anomaly", "wireless.alert.signal_anomaly" -> Optional.of(WIRELESS_SIGNAL_ANOMALY);
            case "wireless.pmf_attack", "wireless.alert.pmf_attack" -> Optional.of(WIRELESS_PMF_ATTACK);
            case "wireless.client_inventory", "wireless.client.inventory" -> Optional.of(WIRELESS_CLIENT_INVENTORY);
            case "wireless.probe_requests", "wireless.probe.flush" -> Optional.of(WIRELESS_PROBE_REQUESTS);
            default -> Optional.empty();
        };
    }
}
