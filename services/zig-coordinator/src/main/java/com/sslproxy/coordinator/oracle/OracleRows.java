package com.sslproxy.coordinator.oracle;

import java.time.OffsetDateTime;
import java.util.List;

record OracleRowSet(
        List<ProxyEventInsert> proxyEvents,
        List<BlockedEventInsert> blockedEvents,
        List<ProxyPayloadAuditInsert> proxyPayloadAudit,
        List<WirelessAuditFrameInsert> wirelessAuditFrames,
        List<WirelessBandwidthInsert> wirelessBandwidth,
        List<WirelessRogueApInsert> wirelessRogueAp,
        List<WirelessDeauthFloodInsert> wirelessDeauthFlood,
        List<WirelessSignalAnomalyInsert> wirelessSignalAnomaly,
        List<WirelessPmfAttackInsert> wirelessPmfAttack,
        List<WirelessClientInventoryInsert> wirelessClientInventory,
        List<WirelessProbeRequestInsert> wirelessProbeRequests
) {
    static OracleRowSet empty() {
        return new OracleRowSet(
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of()
        );
    }

    int inputRowCount(OracleSinkTarget target) {
        return switch (target) {
            case PROXY_EVENTS -> proxyEvents.size();
            case PROXY_PAYLOAD_AUDIT -> proxyPayloadAudit.size();
            case WIRELESS_AUDIT_FRAMES -> wirelessAuditFrames.size();
            case WIRELESS_BANDWIDTH -> wirelessBandwidth.size();
            case WIRELESS_ROGUE_AP -> wirelessRogueAp.size();
            case WIRELESS_DEAUTH_FLOOD -> wirelessDeauthFlood.size();
            case WIRELESS_SIGNAL_ANOMALY -> wirelessSignalAnomaly.size();
            case WIRELESS_PMF_ATTACK -> wirelessPmfAttack.size();
            case WIRELESS_CLIENT_INVENTORY -> wirelessClientInventory.size();
            case WIRELESS_PROBE_REQUESTS -> wirelessProbeRequests.size();
        };
    }
}

record ProxyEventInsert(
        OffsetDateTime eventTime,
        String eventType,
        String host,
        String peerIp,
        String wgPubkey,
        String deviceId,
        String identitySource,
        String peerHostname,
        String clientUa,
        long bytesUp,
        long bytesDown,
        Long statusCode,
        long blocked,
        String obfuscationProfile,
        String correlationId,
        String parentEventId,
        Long eventSequence,
        Long durationMs,
        String reason,
        String rawJson
) {}

record BlockedEventInsert(
        long rowSequence,
        String host,
        long blockedBytes,
        Double frequencyHz,
        Double riskScore,
        String category,
        String verdict,
        long tarpitHeldMs,
        Long iatMs,
        Long consecutiveBlocks,
        String lastVerdict,
        String tlsVer,
        String alpn,
        String ja3Lite,
        String resolvedIp,
        String asnOrg
) {}

record ProxyPayloadAuditInsert(
        String correlationId,
        String host,
        String direction,
        OffsetDateTime capturedAt,
        long byteOffset,
        String payloadObjectKey,
        String contentType,
        String httpMethod,
        Long httpStatus,
        String httpPath,
        long isEncrypted,
        long truncated,
        String peerIp,
        String notes
) {}

record WirelessAuditFrameInsert(
        long rowSequence,
        String eventType,
        OffsetDateTime observedAt,
        String sensorId,
        String locationId,
        String iface,
        long channel,
        String frameType,
        String frameSubtype,
        String bssid,
        String sourceMac,
        String destinationMac,
        String transmitterMac,
        String receiverMac,
        String destinationBssid,
        String ssid,
        Long signalDbm,
        Long sequenceNumber,
        long rawLen,
        long isRetry,
        long isMoreData,
        long isPowerSave,
        long isProtected,
        long isToDs,
        long isFromDs,
        long isHandshake,
        long securityFlags,
        String deviceId,
        String username,
        String identitySource,
        String tags,
        String anomalyReasons,
        String rawJson,
        String regDomain
) {}

record WirelessBandwidthInsert(
        long rowSequence,
        long schemaVersion,
        OffsetDateTime windowStart,
        OffsetDateTime windowEnd,
        String sensorId,
        String locationId,
        String iface,
        long channel,
        String sourceMac,
        String destinationBssid,
        String ssid,
        long bytes,
        long frameCount,
        long retryCount,
        long moreDataCount,
        long powerSaveCount,
        Long strongestSignalDbm,
        long histUnder100,
        long hist100500,
        long hist5001000,
        long hist10001500,
        Long interArrivalP50Ms,
        long externalBssid,
        long thresholdExceeded,
        Long wallClockDeltaMs,
        long windowIsPartial,
        OffsetDateTime publishedAt
) {}

record WirelessRogueApInsert(
        long rowSequence,
        OffsetDateTime detectedAt,
        String sensorId,
        String locationId,
        String iface,
        long channel,
        String rogueBssid,
        String ssid,
        Long signalDbm,
        long ssidImpersonation,
        String rawJson
) {}

record WirelessDeauthFloodInsert(
        long rowSequence,
        OffsetDateTime detectedAt,
        String sensorId,
        String locationId,
        String iface,
        long channel,
        String attackerMac,
        String targetBssid,
        String targetSsid,
        long deauthCount,
        long windowSecs,
        long threshold,
        Long signalDbm,
        String rawJson
) {}

record WirelessSignalAnomalyInsert(
        long rowSequence,
        OffsetDateTime detectedAt,
        String sensorId,
        String locationId,
        String sourceMac,
        String bssid,
        String ssid,
        long channel,
        long baselineDbm,
        long observedDbm,
        long dbmDelta,
        long configuredDelta
) {}

record WirelessPmfAttackInsert(
        long rowSequence,
        OffsetDateTime detectedAt,
        String sensorId,
        String locationId,
        String targetMac,
        String targetBssid,
        String ssid,
        Long channel,
        String attackTag,
        Long reconnectWindowMs
) {}

record WirelessClientInventoryInsert(
        String sensorId,
        String locationId,
        OffsetDateTime snapshotAt,
        String clientMac,
        String bssid,
        String ssid,
        String deviceId,
        String username,
        String identitySource,
        OffsetDateTime lastSeen,
        OffsetDateTime firstSeen,
        Long signalDbm,
        long isAuthorized
) {}

record WirelessProbeRequestInsert(
        long rowSequence,
        String clientMac,
        String ssid,
        String knownBssid,
        OffsetDateTime firstSeen,
        OffsetDateTime lastSeen,
        long probeCount
) {}
