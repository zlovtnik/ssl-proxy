package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PreDestroy;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.ListOffsetsResult.ListOffsetsResultInfo;
import org.apache.kafka.clients.admin.OffsetSpec;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Publishes coordinator-owned Redpanda consumer lag gauges for KEDA readiness.
 *
 * The service keeps the last successful values on refresh failure and exposes
 * refresh-failure/staleness metrics so autoscaling never sees a false zero.
 */
@Service
public class RedpandaLagMetricsService {

    private static final Logger log = LoggerFactory.getLogger(RedpandaLagMetricsService.class);

    private final CoordinatorProperties props;
    private final Supplier<AdminClient> adminClientSupplier;
    private final Clock clock;
    private final Map<LagTarget, TargetMeters> metersByTarget;
    private volatile AdminClient adminClient;
    private volatile boolean disabledLogged = false;

    @Autowired
    public RedpandaLagMetricsService(MeterRegistry registry, CoordinatorProperties props) {
        this(registry, props, () -> AdminClient.create(adminClientConfig(props)), Clock.systemUTC());
    }

    // CGLIB proxy constructor — null/empty defaults, never invoked on the proxy directly
    RedpandaLagMetricsService() {
        this.props = null;
        this.adminClientSupplier = null;
        this.clock = null;
        this.metersByTarget = Map.of();
    }

    RedpandaLagMetricsService(MeterRegistry registry,
                              CoordinatorProperties props,
                              Supplier<AdminClient> adminClientSupplier,
                              Clock clock) {
        this.props = props;
        this.adminClientSupplier = adminClientSupplier;
        this.clock = clock;
        this.metersByTarget = registerMeters(registry, targets(props), clock);
    }

    @Scheduled(fixedDelayString = "${coordinator.redpanda-lag-metrics-poll-interval-ms:10000}")
    public void refresh() {
        if (!props.redpandaLagMetricsEnabled()) {
            logDisabledOnce();
            return;
        }

        for (LagTarget target : metersByTarget.keySet()) {
            refreshTarget(target);
        }
    }

    @PreDestroy
    public void close() {
        AdminClient client = adminClient;
        if (client != null) {
            client.close();
        }
    }

    static LagSnapshot calculateLag(Collection<TopicPartition> partitions,
                                    Map<TopicPartition, Long> endOffsets,
                                    Map<TopicPartition, Long> committedOffsets) {
        long endTotal = 0;
        long committedTotal = 0;
        long lagTotal = 0;

        for (TopicPartition partition : partitions.stream()
                .sorted(Comparator.comparing((TopicPartition partition) -> partition.topic())
                        .thenComparingInt(partition -> partition.partition()))
                .toList()) {
            long end = Math.max(0, endOffsets.getOrDefault(partition, 0L));
            long committed = Math.max(0, committedOffsets.getOrDefault(partition, 0L));
            endTotal += end;
            committedTotal += committed;
            lagTotal += Math.max(0, end - committed);
        }

        return new LagSnapshot(lagTotal, endTotal, committedTotal);
    }

    static String normalizeBootstrapServers(String rawServers) {
        if (rawServers == null || rawServers.isBlank()) {
            return "localhost:9092";
        }

        String normalized = List.of(rawServers.split(",")).stream()
                .map(value -> value.trim())
                .filter(value -> !value.isEmpty())
                .map(RedpandaLagMetricsService::normalizeBootstrapServer)
                .collect(Collectors.joining(","));

        return normalized.isEmpty() ? "localhost:9092" : normalized;
    }

    void recordSuccess(LagTarget target, LagSnapshot snapshot) {
        TargetMeters meters = metersByTarget.get(target);
        if (meters == null) {
            return;
        }
        meters.lagRecords().set(snapshot.lagRecords());
        meters.endOffsetRecords().set(snapshot.endOffsetRecords());
        meters.committedOffsetRecords().set(snapshot.committedOffsetRecords());
        meters.lastSuccessEpochMillis().set(clock.millis());
    }

    List<LagTarget> targets() {
        return List.copyOf(metersByTarget.keySet());
    }

    private void refreshTarget(LagTarget target) {
        try {
            LagSnapshot snapshot = fetchLagSnapshot(getOrCreateAdminClient(), target);
            recordSuccess(target, snapshot);
            log.atDebug()
                    .addKeyValue("event", "redpanda_lag_metrics")
                    .addKeyValue("status", "refreshed")
                    .addKeyValue("role", target.role())
                    .addKeyValue("consumer_group", target.consumerGroup())
                    .addKeyValue("topic", target.topic())
                    .addKeyValue("lag_records", snapshot.lagRecords())
                    .addKeyValue("end_offset_records", snapshot.endOffsetRecords())
                    .addKeyValue("committed_offset_records", snapshot.committedOffsetRecords())
                    .log("redpanda lag metrics refreshed");
        } catch (Exception e) {
            TargetMeters meters = metersByTarget.get(target);
            if (meters != null) {
                meters.refreshFailures().increment();
            }
            log.atWarn()
                    .addKeyValue("event", "redpanda_lag_metrics")
                    .addKeyValue("status", "refresh_failed")
                    .addKeyValue("role", target.role())
                    .addKeyValue("consumer_group", target.consumerGroup())
                    .addKeyValue("topic", target.topic())
                    .addKeyValue("error_class", e.getClass().getSimpleName())
                    .addKeyValue("error", sanitize(e.getMessage()))
                    .log("redpanda lag metrics refresh failed");
        }
    }

    private LagSnapshot fetchLagSnapshot(AdminClient client, LagTarget target) throws Exception {
        int timeoutMs = Math.max(1, props.redpandaLagMetricsTimeoutMs());
        TopicDescription description = client.describeTopics(List.of(target.topic()))
                .topicNameValues()
                .get(target.topic())
                .get(timeoutMs, TimeUnit.MILLISECONDS);

        List<TopicPartition> partitions = description.partitions().stream()
                .map(info -> new TopicPartition(target.topic(), info.partition()))
                .toList();

        Map<TopicPartition, OffsetSpec> latestOffsetRequests = partitions.stream()
                .collect(Collectors.toMap(partition -> partition, ignored -> OffsetSpec.latest()));
        Map<TopicPartition, ListOffsetsResultInfo> latestOffsets = client.listOffsets(latestOffsetRequests)
                .all()
                .get(timeoutMs, TimeUnit.MILLISECONDS);
        Map<TopicPartition, Long> endOffsets = latestOffsets.entrySet().stream()
                .collect(Collectors.toMap(entry -> entry.getKey(), entry -> entry.getValue().offset()));

        Map<TopicPartition, OffsetAndMetadata> committedMetadata = client
                .listConsumerGroupOffsets(target.consumerGroup())
                .partitionsToOffsetAndMetadata()
                .get(timeoutMs, TimeUnit.MILLISECONDS);
        Map<TopicPartition, Long> committedOffsets = committedMetadata.entrySet().stream()
                .filter(entry -> target.topic().equals(entry.getKey().topic()))
                .filter(entry -> entry.getValue() != null)
                .collect(Collectors.toMap(entry -> entry.getKey(), entry -> entry.getValue().offset()));

        return calculateLag(partitions, endOffsets, committedOffsets);
    }

    private AdminClient getOrCreateAdminClient() {
        AdminClient client = adminClient;
        if (client == null) {
            synchronized (this) {
                client = adminClient;
                if (client == null) {
                    client = adminClientSupplier.get();
                    adminClient = client;
                }
            }
        }
        return client;
    }

    private static Map<LagTarget, TargetMeters> registerMeters(MeterRegistry registry, List<LagTarget> targets, Clock clock) {
        Map<LagTarget, TargetMeters> meters = new LinkedHashMap<>();
        long now = clock.millis();

        for (LagTarget target : targets) {
            TargetMeters targetMeters = new TargetMeters(
                    new AtomicLong(0),
                    new AtomicLong(0),
                    new AtomicLong(0),
                    new AtomicLong(now),
                    clock,
                    Counter.builder("coordinator.redpanda.lag.refresh.failures.total")
                            .description("Total Redpanda lag metric refresh failures")
                            .tag("role", target.role())
                            .register(registry)
            );

            Gauge.builder("coordinator.redpanda.consumer.lag.records", targetMeters.lagRecords(), value -> value.get())
                    .description("Aggregated Redpanda consumer lag in records")
                    .tag("role", target.role())
                    .tag("consumer_group", target.consumerGroup())
                    .tag("topic", target.topic())
                    .register(registry);

            Gauge.builder("coordinator.redpanda.topic.end.offset.records", targetMeters.endOffsetRecords(), value -> value.get())
                    .description("Aggregated Redpanda topic end offset in records")
                    .tag("role", target.role())
                    .tag("consumer_group", target.consumerGroup())
                    .tag("topic", target.topic())
                    .register(registry);

            Gauge.builder("coordinator.redpanda.consumer.committed.offset.records", targetMeters.committedOffsetRecords(), value -> value.get())
                    .description("Aggregated Redpanda consumer committed offset in records")
                    .tag("role", target.role())
                    .tag("consumer_group", target.consumerGroup())
                    .tag("topic", target.topic())
                    .register(registry);

            Gauge.builder("coordinator.redpanda.lag.stale.seconds", targetMeters, metersForTarget -> metersForTarget.staleSeconds())
                    .description("Seconds since the last successful Redpanda lag metric refresh")
                    .tag("role", target.role())
                    .tag("consumer_group", target.consumerGroup())
                    .tag("topic", target.topic())
                    .register(registry);

            meters.put(target, targetMeters);
        }

        return meters;
    }

    private static List<LagTarget> targets(CoordinatorProperties props) {
        return List.of(
                new LagTarget("scan", props.scanConsumer(), props.scanTopic()),
                new LagTarget("result", props.resultConsumer(), props.resultTopic())
        );
    }

    private static Properties adminClientConfig(CoordinatorProperties props) {
        int timeoutMs = Math.max(1, props.redpandaLagMetricsTimeoutMs());
        Properties config = new Properties();
        config.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, normalizeBootstrapServers(props.syncRedpandaUrl()));
        config.put(AdminClientConfig.CLIENT_ID_CONFIG, "java-coordinator-lag-metrics");
        config.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, Integer.toString(timeoutMs));
        config.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, Integer.toString(timeoutMs));
        return config;
    }

    private static String normalizeBootstrapServer(String server) {
        int schemeIndex = server.indexOf("://");
        String normalized = schemeIndex >= 0 ? server.substring(schemeIndex + 3) : server;
        int slashIndex = normalized.indexOf('/');
        if (slashIndex >= 0) {
            normalized = normalized.substring(0, slashIndex);
        }
        int credentialIndex = normalized.lastIndexOf('@');
        if (credentialIndex >= 0) {
            normalized = normalized.substring(credentialIndex + 1);
        }
        return normalized;
    }

    private static String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }

    private void logDisabledOnce() {
        if (disabledLogged) {
            return;
        }
        disabledLogged = true;
        log.atInfo()
                .addKeyValue("event", "redpanda_lag_metrics")
                .addKeyValue("status", "disabled")
                .log("redpanda lag metrics disabled");
    }

    record LagTarget(String role, String consumerGroup, String topic) {}

    record LagSnapshot(long lagRecords, long endOffsetRecords, long committedOffsetRecords) {}

    private record TargetMeters(AtomicLong lagRecords,
                                AtomicLong endOffsetRecords,
                                AtomicLong committedOffsetRecords,
                                AtomicLong lastSuccessEpochMillis,
                                Clock clock,
                                Counter refreshFailures) {
        double staleSeconds() {
            long elapsedMillis = Math.max(0, clock.millis() - lastSuccessEpochMillis.get());
            return elapsedMillis / 1000.0;
        }
    }
}
