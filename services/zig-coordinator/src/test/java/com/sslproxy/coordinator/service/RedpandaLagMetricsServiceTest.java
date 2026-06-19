package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RedpandaLagMetricsServiceTest {

    @Test
    void calculatesLagAcrossPartitions() {
        TopicPartition p0 = new TopicPartition("sync.scan.request", 0);
        TopicPartition p1 = new TopicPartition("sync.scan.request", 1);

        RedpandaLagMetricsService.LagSnapshot snapshot = RedpandaLagMetricsService.calculateLag(
                List.of(p0, p1),
                Map.of(p0, 100L, p1, 200L),
                Map.of(p0, 90L, p1, 150L)
        );

        assertEquals(60, snapshot.lagRecords());
        assertEquals(300, snapshot.endOffsetRecords());
        assertEquals(240, snapshot.committedOffsetRecords());
    }

    @Test
    void treatsMissingCommittedOffsetAsFullTopicLag() {
        TopicPartition p0 = new TopicPartition("sync.scan.request", 0);

        RedpandaLagMetricsService.LagSnapshot snapshot = RedpandaLagMetricsService.calculateLag(
                List.of(p0),
                Map.of(p0, 100L),
                Map.of()
        );

        assertEquals(100, snapshot.lagRecords());
        assertEquals(100, snapshot.endOffsetRecords());
        assertEquals(0, snapshot.committedOffsetRecords());
    }

    @Test
    void clampsNegativeLagToZero() {
        TopicPartition p0 = new TopicPartition("sync.scan.request", 0);

        RedpandaLagMetricsService.LagSnapshot snapshot = RedpandaLagMetricsService.calculateLag(
                List.of(p0),
                Map.of(p0, 100L),
                Map.of(p0, 120L)
        );

        assertEquals(0, snapshot.lagRecords());
        assertEquals(100, snapshot.endOffsetRecords());
        assertEquals(120, snapshot.committedOffsetRecords());
    }

    @Test
    void aggregatesMultiPartitionLagWithMissingAndOverCommittedPartitions() {
        TopicPartition p0 = new TopicPartition("sync.oracle.result", 0);
        TopicPartition p1 = new TopicPartition("sync.oracle.result", 1);
        TopicPartition p2 = new TopicPartition("sync.oracle.result", 2);

        RedpandaLagMetricsService.LagSnapshot snapshot = RedpandaLagMetricsService.calculateLag(
                List.of(p0, p1, p2),
                Map.of(p0, 50L, p1, 75L, p2, 25L),
                Map.of(p0, 20L, p2, 30L)
        );

        assertEquals(105, snapshot.lagRecords());
        assertEquals(150, snapshot.endOffsetRecords());
        assertEquals(50, snapshot.committedOffsetRecords());
    }

    @Test
    void registersStableLowCardinalityMeters() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CoordinatorProperties props = coordinatorProperties();
        RedpandaLagMetricsService service = new RedpandaLagMetricsService(
                registry,
                props,
                () -> {
                    throw new IllegalStateException("not used");
                },
                Clock.systemUTC()
        );

        RedpandaLagMetricsService.LagTarget scanTarget = service.targets().stream()
                .filter(target -> "scan".equals(target.role()))
                .findFirst()
                .orElseThrow();
        service.recordSuccess(scanTarget, new RedpandaLagMetricsService.LagSnapshot(42, 100, 58));

        Gauge lagGauge = registry.find("coordinator.redpanda.consumer.lag.records")
                .tags("role", "scan", "consumer_group", "zig-coordinator-scan", "topic", "sync.scan.request")
                .gauge();

        assertNotNull(lagGauge);
        assertEquals(42.0, lagGauge.value());
        Meter.Id id = lagGauge.getId();
        assertEquals(3, id.getTags().size());
    }

    @Test
    void refreshFailureKeepsLastSuccessfulGaugeValueAndMarksStaleness() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        MutableClock clock = new MutableClock(Instant.parse("2026-05-30T12:00:00Z"));
        RedpandaLagMetricsService service = new RedpandaLagMetricsService(
                registry,
                coordinatorProperties(),
                () -> {
                    throw new IllegalStateException("broker unavailable");
                },
                clock
        );

        RedpandaLagMetricsService.LagTarget scanTarget = service.targets().stream()
                .filter(target -> "scan".equals(target.role()))
                .findFirst()
                .orElseThrow();
        service.recordSuccess(scanTarget, new RedpandaLagMetricsService.LagSnapshot(42, 100, 58));

        clock.advanceMillis(5_000);
        service.refresh();

        Gauge lagGauge = registry.find("coordinator.redpanda.consumer.lag.records")
                .tags("role", "scan", "consumer_group", "zig-coordinator-scan", "topic", "sync.scan.request")
                .gauge();
        Gauge staleGauge = registry.find("coordinator.redpanda.lag.stale.seconds")
                .tags("role", "scan", "consumer_group", "zig-coordinator-scan", "topic", "sync.scan.request")
                .gauge();

        assertNotNull(lagGauge);
        assertNotNull(staleGauge);
        assertEquals(42.0, lagGauge.value());
        assertTrue(staleGauge.value() >= 5.0);
        assertEquals(1.0, registry.find("coordinator.redpanda.lag.refresh.failures.total")
                .tag("role", "scan")
                .counter()
                .count());
    }

    @Test
    void stripsRedpandaSchemeAndCredentialsFromBootstrapServers() {
        assertEquals(
                "redpanda:9092,broker-2:9092",
                RedpandaLagMetricsService.normalizeBootstrapServers(
                        "redpanda://user:secret@redpanda:9092,tls://broker-2:9092"
                )
        );
    }

    private CoordinatorProperties coordinatorProperties() {
        CoordinatorProperties d = CoordinatorProperties.DEFAULTS;
        return new CoordinatorProperties(
            d.streamName(),
            d.streamNames(),
            d.oracleStreamNames(),
            "sync.scan.request",
            d.loadTopic(),
            "sync.oracle.result",
            d.payloadAuditTopic(),
            d.databaseUrl(),
            "redpanda://redpanda:9092",
            d.redpandaTopicManifestFile(),
            d.redpandaPublishTimeoutMs(),
            d.auditStreamName(),
            d.resultStreamName(),
            "zig-coordinator-scan",
            d.loadConsumer(),
            "zig-coordinator-result",
            d.payloadAuditConsumer(),
            d.wirelessBacklogStreamName(),
            d.wirelessMacStreamName(),
            d.wirelessNetworksStreamName(),
            d.wirelessProbeStreamName(),
            d.wirelessBacklogSaveTopic(),
            d.wirelessBacklogListTopic(),
            d.wirelessBacklogSyncedTopic(),
            d.wirelessBacklogPruneTopic(),
            d.wirelessMacLookupTopic(),
            d.wirelessNetworksAuthorizedTopic(),
            d.wirelessProbeFlushTopic(),
            d.wirelessBacklogSaveConsumer(),
            d.wirelessBacklogListConsumer(),
            d.wirelessBacklogSyncedConsumer(),
            d.wirelessBacklogPruneConsumer(),
            d.wirelessMacLookupConsumer(),
            d.wirelessNetworksAuthorizedConsumer(),
            d.wirelessProbeFlushConsumer(),
            d.wirelessBacklogListReplyTopic(),
            d.wirelessBacklogPruneReplyTopic(),
            d.wirelessMacLookupReplyTopic(),
            d.wirelessNetworksAuthorizedReplyTopic(),
            d.wirelessRawArchiveEnabled(),
            d.wirelessRawPayloadHotDays(),
            d.syncEventRowRetentionDays(),
            d.syncEventTombstoneRetentionDays(),
            d.wirelessRawArchiveBatchSize(),
            d.retentionPruneBatchSize(),
            d.wirelessRawArchiveIntervalMs(),
            d.retentionMaintenanceIntervalMs(),
            d.wirelessRawArchiveBucket(),
            d.minioEndpoint(),
            d.minioAccessKeyId(),
            d.minioSecretAccessKey(),
            d.syncOutboxDir(),
            d.scanMaxAttempts(),
            d.scanRetryBackoffSeconds(),
            d.batchDispatchLeaseSeconds(),
            d.batchMaxAttempts(),
            d.scanFetchCount(),
            d.resultFetchCount(),
            d.scanConsumersCount(),
            d.resultConsumersCount(),
            d.wirelessConsumersCount(),
            d.wirelessMaxPollRecords(),
            d.ingestBatchSize(),
            d.dispatchBatchSize(),
            d.idleSleepMs(),
            d.idleSleepBackoffMs(),
            d.backpressureBudgetMultiplier(),
            d.adaptivePullChangeThreshold(),
            d.adaptivePullMinRestartIntervalMs(),
            d.redpandaLagMetricsEnabled(),
            d.redpandaLagMetricsPollIntervalMs(),
            100,
            d.heartbeatLogIntervalMs(),
            d.mode()
        );
    }

    private static final class MutableClock extends Clock {
        private final AtomicLong millis;

        private MutableClock(Instant instant) {
            this.millis = new AtomicLong(instant.toEpochMilli());
        }

        private void advanceMillis(long deltaMillis) {
            millis.addAndGet(deltaMillis);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis.get());
        }

        @Override
        public long millis() {
            return millis.get();
        }
    }
}
