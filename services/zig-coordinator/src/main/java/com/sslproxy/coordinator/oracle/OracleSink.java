package com.sslproxy.coordinator.oracle;

public interface OracleSink {
    long insertProxyEvents(String batchId, java.util.List<ProxyEventInsert> rows,
                           java.util.List<BlockedEventInsert> blockedRows) throws Exception;

    long insertProxyPayloadAudit(String batchId, java.util.List<ProxyPayloadAuditInsert> rows) throws Exception;

    long insertWirelessAuditFrames(String batchId, java.util.List<WirelessAuditFrameInsert> rows) throws Exception;

    long insertWirelessBandwidth(String batchId, java.util.List<WirelessBandwidthInsert> rows) throws Exception;

    long insertWirelessRogueAp(String batchId, java.util.List<WirelessRogueApInsert> rows) throws Exception;

    long insertWirelessDeauthFlood(String batchId, java.util.List<WirelessDeauthFloodInsert> rows) throws Exception;

    long insertWirelessSignalAnomaly(String batchId, java.util.List<WirelessSignalAnomalyInsert> rows) throws Exception;

    long insertWirelessPmfAttack(String batchId, java.util.List<WirelessPmfAttackInsert> rows) throws Exception;

    long insertWirelessClientInventory(String batchId, java.util.List<WirelessClientInventoryInsert> rows) throws Exception;

    long insertWirelessProbeRequests(String batchId, java.util.List<WirelessProbeRequestInsert> rows) throws Exception;
}
