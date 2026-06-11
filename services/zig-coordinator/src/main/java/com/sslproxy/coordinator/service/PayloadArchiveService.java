package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class PayloadArchiveService {

    private static final Logger log = LoggerFactory.getLogger(PayloadArchiveService.class);
    private static final DateTimeFormatter ARCHIVE_DATE = DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC);

    private final DatabaseService databaseService;
    private final CoordinatorProperties props;
    private final MinioClient minioClient;
    private volatile boolean bucketChecked;

    public PayloadArchiveService(DatabaseService databaseService, CoordinatorProperties props) {
        this.databaseService = databaseService;
        this.props = props;
        if (props.isWirelessRawArchiveEnabled()
                && (!StringUtils.hasText(props.getMinioAccessKeyId())
                || !StringUtils.hasText(props.getMinioSecretAccessKey()))) {
            throw new IllegalStateException(
                    "wireless raw archive is enabled but MinIO credentials are not configured");
        }
        this.minioClient = MinioClient.builder()
                .endpoint(props.getMinioEndpoint())
                .credentials(props.getMinioAccessKeyId(), props.getMinioSecretAccessKey())
                .build();
    }

    public int archiveDuePayloads() {
        if (!props.isWirelessRawArchiveEnabled()) {
            return 0;
        }

        try {
            ensureBucket();
        } catch (Exception e) {
            log.warn("event=wireless_payload_archive status=bucket_unavailable bucket={} error={}",
                    props.getWirelessRawArchiveBucket(), e.getMessage());
            return 0;
        }

        List<DatabaseService.PayloadArchiveCandidate> candidates = switch (databaseService.listWirelessPayloadArchiveCandidates()) {
            case DbResult.Ok<List<DatabaseService.PayloadArchiveCandidate>> ok -> ok.value();
            case DbResult.Empty<List<DatabaseService.PayloadArchiveCandidate>> ignored -> List.of();
            case DbResult.Err<List<DatabaseService.PayloadArchiveCandidate>> err -> {
                log.warn("event=wireless_payload_archive status=list_candidates_failed operation={} error={}",
                        err.operation(), sanitize(err.cause().getMessage()));
                yield List.of();
            }
        };
        int archived = 0;
        for (DatabaseService.PayloadArchiveCandidate candidate : candidates) {
            if (candidate.payloadJson() == null || candidate.payloadJson().isBlank()) {
                continue;
            }
            try {
                byte[] bytes = candidate.payloadJson().getBytes(StandardCharsets.UTF_8);
                String objectName = archiveObjectName(candidate);
                uploadPayload(objectName, bytes);
                String archiveUri = "s3://" + props.getWirelessRawArchiveBucket() + "/" + objectName;
                DbResult<Boolean> recorded = databaseService.recordPayloadArchive(
                        candidate.dedupeKey(),
                        candidate.payloadSha256(),
                        archiveUri,
                        bytes.length);
                if (recorded.orElse(false)) {
                    archived++;
                } else {
                    log.warn("event=wireless_payload_archive status=db_mark_skipped dedupe_key={}", candidate.dedupeKey());
                }
            } catch (Exception e) {
                log.warn("event=wireless_payload_archive status=failed dedupe_key={} error={}",
                        candidate.dedupeKey(), e.getMessage());
            }
        }
        if (archived > 0 || !candidates.isEmpty()) {
            log.info("event=wireless_payload_archive status=complete candidates={} archived={}",
                    candidates.size(), archived);
        }
        return archived;
    }

    public void runRetentionPrune() {
        switch (databaseService.pruneSyncEventRetention()) {
            case DbResult.Ok<String> ok ->
                    log.info("event=sync_event_retention_prune status=complete result={}", ok.value());
            case DbResult.Empty<String> ignored -> {
            }
            case DbResult.Err<String> err ->
                    log.warn("event=sync_event_retention_prune status=failed operation={} error={}",
                            err.operation(), sanitize(err.cause().getMessage()));
        }

        switch (databaseService.pruneVectorRetention()) {
            case DbResult.Ok<String> ok ->
                    log.info("event=vector_retention_prune status=complete result={}", ok.value());
            case DbResult.Empty<String> ignored -> {
            }
            case DbResult.Err<String> err ->
                    log.warn("event=vector_retention_prune status=failed operation={} error={}",
                            err.operation(), sanitize(err.cause().getMessage()));
        }
    }

    String archiveObjectName(DatabaseService.PayloadArchiveCandidate candidate) {
        String datePath = ARCHIVE_DATE.format(candidate.observedAt().toInstant());
        return candidate.streamName() + "/" + datePath + "/" + encodeKey(candidate.dedupeKey()) + ".json";
    }

    private void uploadPayload(String objectName, byte[] bytes) throws Exception {
        try (ByteArrayInputStream input = new ByteArrayInputStream(bytes)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(props.getWirelessRawArchiveBucket())
                            .object(objectName)
                            .stream(input, bytes.length, -1)
                            .contentType("application/json")
                            .build()
            );
        }
    }

    private void ensureBucket() throws Exception {
        if (bucketChecked) {
            return;
        }
        synchronized (this) {
            if (bucketChecked) {
                return;
            }
            String bucket = props.getWirelessRawArchiveBucket();
            boolean exists = minioClient.bucketExists(BucketExistsArgs.builder().bucket(bucket).build());
            if (!exists) {
                try {
                    minioClient.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
                } catch (Exception exception) {
                    String message = exception.getMessage();
                    if (message == null
                            || (!message.contains("BucketAlreadyOwnedByYou")
                            && !message.contains("BucketAlreadyExists"))) {
                        throw exception;
                    }
                }
            }
            bucketChecked = true;
        }
    }

    private String encodeKey(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
