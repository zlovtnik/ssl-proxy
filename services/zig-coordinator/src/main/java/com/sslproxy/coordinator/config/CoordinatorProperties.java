package com.sslproxy.coordinator.config;

import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Maps all coordinator configuration from environment variables.
 * Corresponds to services/zig-coordinator/src/config.zig
 *
 * Immutable record. Spring Boot 3 auto-detects constructor binding
 * for records and classes with a single constructor.
 */
@ConfigurationProperties(prefix = "coordinator")
@Validated
public record CoordinatorProperties(

    // === Stream configuration ===
    String streamName,
    List<String> streamNames,
    List<String> oracleStreamNames,

    // === Redpanda topics ===
    String scanTopic,
    String loadTopic,
    String resultTopic,
    String payloadAuditTopic,

    // === Database ===
    String databaseUrl,

    // === Redpanda ===
    String syncRedpandaUrl,
    String redpandaTopicManifestFile,
    @Min(1) int redpandaPublishTimeoutMs,

    // === Stream names ===
    String auditStreamName,
    String resultStreamName,

    // === Consumer groups ===
    String scanConsumer,
    String loadConsumer,
    String resultConsumer,
    String payloadAuditConsumer,

    // === Wireless stream names ===
    String wirelessBacklogStreamName,
    String wirelessMacStreamName,
    String wirelessNetworksStreamName,
    String wirelessProbeStreamName,

    // === Wireless operation topics ===
    String wirelessBacklogSaveTopic,
    String wirelessBacklogListTopic,
    String wirelessBacklogSyncedTopic,
    String wirelessBacklogPruneTopic,
    String wirelessMacLookupTopic,
    String wirelessNetworksAuthorizedTopic,
    String wirelessProbeFlushTopic,

    // === Wireless consumer groups ===
    String wirelessBacklogSaveConsumer,
    String wirelessBacklogListConsumer,
    String wirelessBacklogSyncedConsumer,
    String wirelessBacklogPruneConsumer,
    String wirelessMacLookupConsumer,
    String wirelessNetworksAuthorizedConsumer,
    String wirelessProbeFlushConsumer,

    // === Wireless reply topics ===
    String wirelessBacklogListReplyTopic,
    String wirelessBacklogPruneReplyTopic,
    String wirelessMacLookupReplyTopic,
    String wirelessNetworksAuthorizedReplyTopic,

    // === Wireless raw payload archive and retention ===
    boolean wirelessRawArchiveEnabled,
    @Min(1) int wirelessRawPayloadHotDays,
    @Min(1) int syncEventRowRetentionDays,
    @Min(1) int syncEventTombstoneRetentionDays,
    @Min(1) int wirelessRawArchiveBatchSize,
    @Min(1) int retentionPruneBatchSize,
    @Min(1) int wirelessRawArchiveIntervalMs,
    @Min(1) int retentionMaintenanceIntervalMs,
    String wirelessRawArchiveBucket,
    String minioEndpoint,
    String minioAccessKeyId,
    String minioSecretAccessKey,

    // === Outbox ===
    String syncOutboxDir,

    // === Retry & batch tuning ===
    @Min(1) int scanMaxAttempts,
    @Min(1) int scanRetryBackoffSeconds,
    @Min(1) int batchDispatchLeaseSeconds,
    @Min(1) int batchMaxAttempts,

    // === Batch tuning for high-throughput consumption ===
    @Min(1) int scanFetchCount,
    @Min(1) int resultFetchCount,
    @Min(1) int scanConsumersCount,
    @Min(1) int resultConsumersCount,
    @Min(1) int wirelessConsumersCount,
    @Min(1) int wirelessMaxPollRecords,
    @Min(1) int ingestBatchSize,
    @Min(1) int dispatchBatchSize,
    @Min(1) int idleSleepMs,
    @Min(1) int idleSleepBackoffMs,

    // === Backpressure & adaptive pull ===
    @Min(1) int backpressureBudgetMultiplier,
    @Min(1) int adaptivePullChangeThreshold,
    @Min(1) int adaptivePullMinRestartIntervalMs,
    boolean redpandaLagMetricsEnabled,
    @Min(1) int redpandaLagMetricsPollIntervalMs,
    @Min(1) int redpandaLagMetricsTimeoutMs,
    @Min(1) int heartbeatLogIntervalMs,

    // === Health check ===
    String mode

) {

    /**
     * Default instance used when Spring Boot doesn't override fields.
     * Matches the defaults in application.yaml.
     */
    public static final CoordinatorProperties DEFAULTS = new CoordinatorProperties(
        "proxy.events",
        List.of("proxy.events", "wireless.audit", "audit.wireless.bandwidth",
                "wireless.alert.rogue_ap", "wireless.alert.deauth_flood",
                "wireless.alert.signal_anomaly", "wireless.alert.pmf_attack",
                "wireless.client.inventory", "wireless.probe.flush", "proxy.payload_audit"),
        List.of("proxy.events", "wireless.audit", "audit.wireless.bandwidth",
                "wireless.alert.rogue_ap", "wireless.alert.deauth_flood",
                "wireless.alert.signal_anomaly", "wireless.alert.pmf_attack",
                "wireless.client.inventory", "wireless.probe.flush", "proxy.payload_audit"),
        "sync.scan.request",
        "sync.oracle.load",
        "sync.oracle.result",
        "proxy.payload_audit",
        "",
        "",
        "/app/docker/redpanda/topics.manifest",
        10_000,
        "AUDIT_STREAM",
        "ORACLE_RESULT_STREAM",
        "zig-coordinator-scan",
        "oracle-worker-load",
        "zig-coordinator-result",
        "zig-coordinator-payload-audit",
        "WIRELESS_BACKLOG_STREAM",
        "WIRELESS_MAC_STREAM",
        "WIRELESS_NETWORKS_STREAM",
        "WIRELESS_PROBE_STREAM",
        "wireless.backlog.save",
        "wireless.backlog.list",
        "wireless.backlog.synced",
        "wireless.backlog.prune",
        "wireless.mac.lookup",
        "wireless.networks.authorized",
        "wireless.probe.flush",
        "wireless-backlog-save",
        "wireless-backlog-list",
        "wireless-backlog-synced",
        "wireless-backlog-prune",
        "wireless-mac-lookup",
        "wireless-networks-authorized",
        "wireless-probe-flush",
        "wireless.backlog.list.reply",
        "wireless.backlog.prune.reply",
        "wireless.mac.lookup.reply",
        "wireless.networks.authorized.reply",
        true, 7, 30, 45, 100, 5000, 300_000, 3_600_000,
        "ssl-proxy-wireless-raw-archive",
        "http://minio:9000",
        "", "",
        "/sync-outbox",
        5, 30, 300, 5,
        500, 200, 1, 1, 1, 1,
        1000, 50, 250, 1000,
        4, 50, 10_000,
        true, 10_000, 5_000, 15_000,
        "run"
    );
}
