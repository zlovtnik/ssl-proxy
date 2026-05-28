package com.sslproxy.coordinator.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Maps all coordinator configuration from environment variables.
 * Corresponds to services/zig-coordinator/src/config.zig
 */
@ConfigurationProperties(prefix = "coordinator")
@Validated
public class CoordinatorProperties {

    // === Stream configuration ===
    private String streamName = "proxy.events";
    private String streamNames = "proxy.events,wireless.audit,audit.wireless.bandwidth,wireless.alert.rogue_ap,wireless.alert.deauth_flood,wireless.alert.signal_anomaly,wireless.alert.pmf_attack,wireless.client.inventory,wireless.probe.flush";
    private String oracleStreamNames = "proxy.events,wireless.audit,audit.wireless.bandwidth,wireless.alert.rogue_ap,wireless.alert.deauth_flood,wireless.alert.signal_anomaly,wireless.alert.pmf_attack,wireless.client.inventory,wireless.probe.flush";

    // === Redpanda topics ===
    private String scanTopic = "sync.scan.request";
    private String loadTopic = "sync.oracle.load";
    private String resultTopic = "sync.oracle.result";

    // === Database ===
    private String databaseUrl;

    // === Redpanda ===
    private String syncRedpandaUrl;
    private String redpandaTopicManifestFile = "/app/docker/redpanda/topics.manifest";
    private String syncSchemaFile = "/app/sql/postgres.sql";
    private int redpandaPublishTimeoutMs = 10_000;

    // === Stream names ===
    private String auditStreamName = "AUDIT_STREAM";
    private String resultStreamName = "ORACLE_RESULT_STREAM";

    // === Consumer groups ===
    private String scanConsumer = "zig-coordinator-scan";
    private String loadConsumer = "oracle-worker-load";
    private String resultConsumer = "zig-coordinator-result";

    // === Wireless stream names ===
    private String wirelessBacklogStreamName = "WIRELESS_BACKLOG_STREAM";
    private String wirelessMacStreamName = "WIRELESS_MAC_STREAM";
    private String wirelessNetworksStreamName = "WIRELESS_NETWORKS_STREAM";
    private String wirelessProbeStreamName = "WIRELESS_PROBE_STREAM";

    // === Wireless consumer groups ===
    private String wirelessBacklogSaveConsumer = "wireless-backlog-save";
    private String wirelessBacklogListConsumer = "wireless-backlog-list";
    private String wirelessBacklogSyncedConsumer = "wireless-backlog-synced";
    private String wirelessBacklogPruneConsumer = "wireless-backlog-prune";
    private String wirelessMacLookupConsumer = "wireless-mac-lookup";
    private String wirelessNetworksAuthorizedConsumer = "wireless-networks-authorized";
    private String wirelessProbeFlushConsumer = "wireless-probe-flush";

    // === Wireless reply topics ===
    private String wirelessBacklogListReplyTopic = "wireless.backlog.list.reply";
    private String wirelessBacklogPruneReplyTopic = "wireless.backlog.prune.reply";
    private String wirelessMacLookupReplyTopic = "wireless.mac.lookup.reply";
    private String wirelessNetworksAuthorizedReplyTopic = "wireless.networks.authorized.reply";

    // === Outbox ===
    private String syncOutboxDir = "/sync-outbox";

    // === Retry & batch tuning ===
    private int scanMaxAttempts = 5;
    private int scanRetryBackoffSeconds = 30;
    private int batchDispatchLeaseSeconds = 300;
    private int batchMaxAttempts = 5;

    // === Batch tuning for high-throughput consumption ===
    private int scanFetchCount = 500;
    private int resultFetchCount = 200;
    private int ingestBatchSize = 1000;
    private int dispatchBatchSize = 50;
    private int idleSleepMs = 250;
    private int idleSleepBackoffMs = 1000;

    // === Backpressure & adaptive pull ===
    private int backpressureBudgetMultiplier = 4;

    // === Health check ===
    private String mode = "run";

    // ========== Getters / Setters ==========

    public String getStreamName() { return streamName; }
    public void setStreamName(String streamName) { this.streamName = streamName; }

    public String getStreamNames() { return streamNames; }
    public void setStreamNames(String streamNames) { this.streamNames = streamNames; }

    public String getOracleStreamNames() { return oracleStreamNames; }
    public void setOracleStreamNames(String oracleStreamNames) { this.oracleStreamNames = oracleStreamNames; }

    public String getScanTopic() { return scanTopic; }
    public void setScanTopic(String scanTopic) { this.scanTopic = scanTopic; }

    public String getLoadTopic() { return loadTopic; }
    public void setLoadTopic(String loadTopic) { this.loadTopic = loadTopic; }

    public String getResultTopic() { return resultTopic; }
    public void setResultTopic(String resultTopic) { this.resultTopic = resultTopic; }

    public String getDatabaseUrl() { return databaseUrl; }
    public void setDatabaseUrl(String databaseUrl) { this.databaseUrl = databaseUrl; }

    public String getSyncRedpandaUrl() { return syncRedpandaUrl; }
    public void setSyncRedpandaUrl(String syncRedpandaUrl) { this.syncRedpandaUrl = syncRedpandaUrl; }

    public String getRedpandaTopicManifestFile() { return redpandaTopicManifestFile; }
    public void setRedpandaTopicManifestFile(String redpandaTopicManifestFile) { this.redpandaTopicManifestFile = redpandaTopicManifestFile; }

    public String getSyncSchemaFile() { return syncSchemaFile; }
    public void setSyncSchemaFile(String syncSchemaFile) { this.syncSchemaFile = syncSchemaFile; }

    public int getRedpandaPublishTimeoutMs() { return redpandaPublishTimeoutMs; }
    public void setRedpandaPublishTimeoutMs(int redpandaPublishTimeoutMs) { this.redpandaPublishTimeoutMs = redpandaPublishTimeoutMs; }

    public String getAuditStreamName() { return auditStreamName; }
    public void setAuditStreamName(String auditStreamName) { this.auditStreamName = auditStreamName; }

    public String getResultStreamName() { return resultStreamName; }
    public void setResultStreamName(String resultStreamName) { this.resultStreamName = resultStreamName; }

    public String getScanConsumer() { return scanConsumer; }
    public void setScanConsumer(String scanConsumer) { this.scanConsumer = scanConsumer; }

    public String getLoadConsumer() { return loadConsumer; }
    public void setLoadConsumer(String loadConsumer) { this.loadConsumer = loadConsumer; }

    public String getResultConsumer() { return resultConsumer; }
    public void setResultConsumer(String resultConsumer) { this.resultConsumer = resultConsumer; }

    public String getWirelessBacklogStreamName() { return wirelessBacklogStreamName; }
    public void setWirelessBacklogStreamName(String wirelessBacklogStreamName) { this.wirelessBacklogStreamName = wirelessBacklogStreamName; }

    public String getWirelessMacStreamName() { return wirelessMacStreamName; }
    public void setWirelessMacStreamName(String wirelessMacStreamName) { this.wirelessMacStreamName = wirelessMacStreamName; }

    public String getWirelessNetworksStreamName() { return wirelessNetworksStreamName; }
    public void setWirelessNetworksStreamName(String wirelessNetworksStreamName) { this.wirelessNetworksStreamName = wirelessNetworksStreamName; }

    public String getWirelessProbeStreamName() { return wirelessProbeStreamName; }
    public void setWirelessProbeStreamName(String wirelessProbeStreamName) { this.wirelessProbeStreamName = wirelessProbeStreamName; }

    public String getWirelessBacklogSaveConsumer() { return wirelessBacklogSaveConsumer; }
    public void setWirelessBacklogSaveConsumer(String wirelessBacklogSaveConsumer) { this.wirelessBacklogSaveConsumer = wirelessBacklogSaveConsumer; }

    public String getWirelessBacklogListConsumer() { return wirelessBacklogListConsumer; }
    public void setWirelessBacklogListConsumer(String wirelessBacklogListConsumer) { this.wirelessBacklogListConsumer = wirelessBacklogListConsumer; }

    public String getWirelessBacklogSyncedConsumer() { return wirelessBacklogSyncedConsumer; }
    public void setWirelessBacklogSyncedConsumer(String wirelessBacklogSyncedConsumer) { this.wirelessBacklogSyncedConsumer = wirelessBacklogSyncedConsumer; }

    public String getWirelessBacklogPruneConsumer() { return wirelessBacklogPruneConsumer; }
    public void setWirelessBacklogPruneConsumer(String wirelessBacklogPruneConsumer) { this.wirelessBacklogPruneConsumer = wirelessBacklogPruneConsumer; }

    public String getWirelessMacLookupConsumer() { return wirelessMacLookupConsumer; }
    public void setWirelessMacLookupConsumer(String wirelessMacLookupConsumer) { this.wirelessMacLookupConsumer = wirelessMacLookupConsumer; }

    public String getWirelessNetworksAuthorizedConsumer() { return wirelessNetworksAuthorizedConsumer; }
    public void setWirelessNetworksAuthorizedConsumer(String wirelessNetworksAuthorizedConsumer) { this.wirelessNetworksAuthorizedConsumer = wirelessNetworksAuthorizedConsumer; }

    public String getWirelessProbeFlushConsumer() { return wirelessProbeFlushConsumer; }
    public void setWirelessProbeFlushConsumer(String wirelessProbeFlushConsumer) { this.wirelessProbeFlushConsumer = wirelessProbeFlushConsumer; }

    public String getWirelessBacklogListReplyTopic() { return wirelessBacklogListReplyTopic; }
    public void setWirelessBacklogListReplyTopic(String wirelessBacklogListReplyTopic) { this.wirelessBacklogListReplyTopic = wirelessBacklogListReplyTopic; }

    public String getWirelessBacklogPruneReplyTopic() { return wirelessBacklogPruneReplyTopic; }
    public void setWirelessBacklogPruneReplyTopic(String wirelessBacklogPruneReplyTopic) { this.wirelessBacklogPruneReplyTopic = wirelessBacklogPruneReplyTopic; }

    public String getWirelessMacLookupReplyTopic() { return wirelessMacLookupReplyTopic; }
    public void setWirelessMacLookupReplyTopic(String wirelessMacLookupReplyTopic) { this.wirelessMacLookupReplyTopic = wirelessMacLookupReplyTopic; }

    public String getWirelessNetworksAuthorizedReplyTopic() { return wirelessNetworksAuthorizedReplyTopic; }
    public void setWirelessNetworksAuthorizedReplyTopic(String wirelessNetworksAuthorizedReplyTopic) { this.wirelessNetworksAuthorizedReplyTopic = wirelessNetworksAuthorizedReplyTopic; }

    public String getSyncOutboxDir() { return syncOutboxDir; }
    public void setSyncOutboxDir(String syncOutboxDir) { this.syncOutboxDir = syncOutboxDir; }

    public int getScanMaxAttempts() { return scanMaxAttempts; }
    public void setScanMaxAttempts(int scanMaxAttempts) { this.scanMaxAttempts = scanMaxAttempts; }

    public int getScanRetryBackoffSeconds() { return scanRetryBackoffSeconds; }
    public void setScanRetryBackoffSeconds(int scanRetryBackoffSeconds) { this.scanRetryBackoffSeconds = scanRetryBackoffSeconds; }

    public int getBatchDispatchLeaseSeconds() { return batchDispatchLeaseSeconds; }
    public void setBatchDispatchLeaseSeconds(int batchDispatchLeaseSeconds) { this.batchDispatchLeaseSeconds = batchDispatchLeaseSeconds; }

    public int getBatchMaxAttempts() { return batchMaxAttempts; }
    public void setBatchMaxAttempts(int batchMaxAttempts) { this.batchMaxAttempts = batchMaxAttempts; }

    public int getScanFetchCount() { return scanFetchCount; }
    public void setScanFetchCount(int scanFetchCount) { this.scanFetchCount = scanFetchCount; }

    public int getResultFetchCount() { return resultFetchCount; }
    public void setResultFetchCount(int resultFetchCount) { this.resultFetchCount = resultFetchCount; }

    public int getIngestBatchSize() { return ingestBatchSize; }
    public void setIngestBatchSize(int ingestBatchSize) { this.ingestBatchSize = ingestBatchSize; }

    public int getDispatchBatchSize() { return dispatchBatchSize; }
    public void setDispatchBatchSize(int dispatchBatchSize) { this.dispatchBatchSize = dispatchBatchSize; }

    public int getIdleSleepMs() { return idleSleepMs; }
    public void setIdleSleepMs(int idleSleepMs) { this.idleSleepMs = idleSleepMs; }

    public int getIdleSleepBackoffMs() { return idleSleepBackoffMs; }
    public void setIdleSleepBackoffMs(int idleSleepBackoffMs) { this.idleSleepBackoffMs = idleSleepBackoffMs; }

    public int getBackpressureBudgetMultiplier() { return backpressureBudgetMultiplier; }
    public void setBackpressureBudgetMultiplier(int backpressureBudgetMultiplier) { this.backpressureBudgetMultiplier = backpressureBudgetMultiplier; }

    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }
}