package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.fp.FpUtils;
import com.sslproxy.coordinator.fp.SqlArrays;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import io.vavr.control.Try;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Wraps all stored procedure calls to the coordinator schema.
 * Corresponds to zig files: db.zig, db_sync.zig, db_wireless.zig
 */
@Service
public class DatabaseService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseService.class);
    private static final int SQL_ARRAY_CHUNK_SIZE = 500;

    private final JdbcTemplate jdbc;
    private final CoordinatorProperties props;
    private final ObservationRegistry observationRegistry;

    public DatabaseService(JdbcTemplate jdbc, CoordinatorProperties props) {
        this(jdbc, props, ObservationRegistry.NOOP);
    }

    @Autowired
    public DatabaseService(JdbcTemplate jdbc, CoordinatorProperties props, ObservationRegistry observationRegistry) {
        this.jdbc = jdbc;
        this.props = props;
        this.observationRegistry = observationRegistry;
    }

    // ========== Connectivity ==========

    /** Quick connectivity check. */
    public DbResult<Void> checkConnectivity() {
        return DbResult.run(
                () -> observeDb("coordinator.check_connectivity", () -> jdbc.queryForObject("SELECT 1", Integer.class)),
                "coordinator.check_connectivity"
        );
    }

    // ========== Cursor management ==========

    /**
     * Ensures a cursor for the given stream name exists.
     * Returns the cursor value.
     */
    public DbResult<String> ensureCursor(String streamName) {
        return DbResult.of(
                () -> observeDb("coordinator.ensure_cursor", () -> jdbc.queryForObject(
                        "SELECT coordinator.ensure_cursor(?::text)::text",
                        String.class,
                        streamName
                )),
                "coordinator.ensure_cursor"
        );
    }

    /**
     * Ensures cursors for all configured streams.
     * Returns the cursor for the primary stream.
     */
    public DbResult<String> ensureAllCursors() {
        return DbResult.of(() -> {
            String primaryCursor = null;
            for (String name : props.streamNames()) {
                String cursor = ensureCursor(name).orElseThrow();
                if (name.equals(props.streamName())) {
                    primaryCursor = cursor;
                }
            }
            if (primaryCursor == null) {
                throw new IllegalStateException("Cursor not found for primary stream: " + props.streamName());
            }
            return primaryCursor;
        }, "coordinator.ensure_all_cursors");
    }

    // ========== Ingest ledger ==========

    /**
     * Returns the count of pending ledger entries.
     * coordinator.pending_ledger_count()
     */
    public DbResult<Long> pendingLedgerCount() {
        return DbResult.of(
                () -> parseLongOrZero(observeDb("coordinator.pending_ledger_count", () -> jdbc.queryForObject(
                        "SELECT coordinator.pending_ledger_count()::text",
                        String.class
                )), "coordinator.pending_ledger_count"),
                "coordinator.pending_ledger_count"
        );
    }

    /**
     * Processes the ingest ledger. Returns number of events processed.
     * coordinator.process_ingest_ledger()
     */
    public DbResult<Long> processIngestLedger() {
        return DbResult.of(() -> {
            String streamNames = joinCsv(props.streamNames());
            String oracleStreamNames = joinCsv(props.oracleStreamNames());
            String result = observeDb("coordinator.process_ingest_ledger", () -> jdbc.queryForObject(
                    "SELECT coordinator.process_ingest_ledger(" +
                            "string_to_array(?::text, ','), " +
                            "string_to_array(?::text, ','), " +
                            "?::integer, ?::integer, ?::integer)::text",
                    String.class,
                    streamNames, oracleStreamNames,
                    props.scanMaxAttempts(),
                    props.scanRetryBackoffSeconds(),
                    props.ingestBatchSize()
            ));
            return parseLongOrZero(result, "coordinator.process_ingest_ledger");
        }, "coordinator.process_ingest_ledger");
    }

    // ========== Scan request recording ==========

    /**
     * Records scan request batches.
     * coordinator.record_scan_request_batch()
     */
    public DbResult<Integer> recordScanRequests(List<ScanRequestRecord> records) {
        return DbResult.of(() -> {
            if (records == null || records.isEmpty()) {
                return 0;
            }
            List<Try<Integer>> chunkResults = FpUtils.partition(records, SQL_ARRAY_CHUNK_SIZE).stream()
                    .map(this::recordScanRequestChunk)
                    .toList();
            return sumChunkResultsOrThrow("coordinator.record_scan_request_batch", chunkResults);
        }, "coordinator.record_scan_request_batch");
    }

    private Try<Integer> recordScanRequestChunk(List<ScanRequestRecord> chunk) {
        List<String> streamNames = props.streamNames();
        return Try.of(() -> {
            Integer recorded = observeDb("coordinator.record_scan_request_batch", () -> jdbc.execute((Connection connection) ->
                    SqlArrays.withJsonbArray(connection, extract(chunk, record -> record.requestJson()), requestArray ->
                            SqlArrays.withJsonbArray(connection, extract(chunk, record -> record.payloadJson()), payloadArray ->
                                    SqlArrays.withTextArray(connection, extract(chunk, record -> record.payloadSha256()), shaArray ->
                                            SqlArrays.withTextArray(connection, streamNames, streamNameArray ->
                                                    queryForInt(
                                                            connection,
                                                            "SELECT coordinator.record_scan_request_batch(?, ?, ?, ?)::text",
                                                            requestArray,
                                                            payloadArray,
                                                            shaArray,
                                                            streamNameArray
                                                    )
                                            ).get()
                                    ).get()
                            ).get()
                    ).get()
            ));
            return recorded == null ? 0 : recorded;
        });
    }

    // ========== Batch dispatch ==========

    /**
     * Gets the next batch to dispatch. Returns the JSON payload or empty.
     * coordinator.get_next_batch()
     */
    public DbResult<String> getNextBatch() {
        return DbResult.of(() -> {
            String oracleStreamNames = joinCsv(props.oracleStreamNames());
            String result = observeDb("coordinator.get_next_batch", () -> jdbc.queryForObject(
                    "SELECT coordinator.get_next_batch(string_to_array(?::text, ','))::text",
                    String.class,
                    oracleStreamNames
            ));
            return blankToNull(result);
        }, "coordinator.get_next_batch");
    }

    /**
     * Recovers stale dispatched batches.
     * coordinator.recover_stale_dispatched_batches()
     */
    public DbResult<Integer> recoverStaleDispatchedBatches() {
        return DbResult.of(() -> {
            String oracleStreamNames = joinCsv(props.oracleStreamNames());
            String result = observeDb("coordinator.recover_stale_dispatched_batches", () -> jdbc.queryForObject(
                    "SELECT coordinator.recover_stale_dispatched_batches(" +
                            "string_to_array(?::text, ','), " +
                            "?::integer, ?::integer)::text",
                    String.class,
                    oracleStreamNames,
                    props.batchDispatchLeaseSeconds(),
                    props.batchMaxAttempts()
            ));
            return parseIntOrZero(result, "coordinator.recover_stale_dispatched_batches");
        }, "coordinator.recover_stale_dispatched_batches");
    }

    /**
     * Marks a batch dispatch as failed.
     * coordinator.mark_batch_dispatch_failed()
     */
    public DbResult<String> markBatchDispatchFailed(String loadJson, String errorText) {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.mark_batch_dispatch_failed", () -> jdbc.queryForObject(
                    "SELECT coordinator.mark_batch_dispatch_failed(?::jsonb, ?::text, ?::integer)::text",
                    String.class,
                    loadJson, errorText, props.batchMaxAttempts()
            ));
            return blankToNull(result);
        }, "coordinator.mark_batch_dispatch_failed");
    }

    /**
     * Releases a batch dispatch with an error.
     * coordinator.release_batch_dispatch()
     */
    public DbResult<String> releaseBatchDispatch(String loadJson, String errorText) {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.release_batch_dispatch", () -> jdbc.queryForObject(
                    "SELECT coordinator.release_batch_dispatch(?::jsonb, ?::text)::text",
                    String.class,
                    loadJson, errorText
            ));
            return blankToNull(result);
        }, "coordinator.release_batch_dispatch");
    }

    /**
     * Repairs an already-published sync.oracle.load message whose payload_ref is
     * blank by rebuilding the ref from the stored sync_events payload.
     */
    public DbResult<String> repairBatchPayloadRef(String batchId) {
        return DbResult.of(() -> {
            List<String> refs = observeDb("coordinator.repair_batch_payload_ref", () -> jdbc.queryForList("""
                    with repaired as (
                      update sync_batches batch
                         set payload_ref = coalesce(
                               nullif(btrim(batch.payload_ref), ''),
                               'inline://json/' ||
                               rtrim(
                                 translate(
                                   replace(encode(convert_to(event.payload::text, 'UTF8'), 'base64'), E'\\n', ''),
                                   '+/',
                                   '-_'
                                 ),
                                 '='
                               )
                             ),
                             updated_at = now()
                        from sync_events event
                       where batch.batch_id = ?::uuid
                         and event.dedupe_key = batch.dedupe_key
                         and nullif(btrim(batch.payload_ref), '') is null
                         and event.payload is not null
                      returning batch.payload_ref
                    ),
                    existing as (
                      select payload_ref
                        from sync_batches
                       where batch_id = ?::uuid
                         and nullif(btrim(payload_ref), '') is not null
                    )
                    select payload_ref from repaired
                    union all
                    select payload_ref from existing
                    limit 1
                    """, String.class, batchId, batchId));
            if (refs.isEmpty()) {
                return null;
            }
            return blankToNull(refs.get(0));
        }, "coordinator.repair_batch_payload_ref");
    }

    // ========== Results ==========

    /**
     * Processes batch results. Returns the number of results processed.
     * coordinator.process_batch_results()
     */
    public DbResult<Integer> processBatchResults(List<String> resultJsons) {
        return DbResult.of(() -> {
            if (resultJsons == null || resultJsons.isEmpty()) {
                return 0;
            }
            List<Try<Integer>> chunkResults = FpUtils.partition(resultJsons, SQL_ARRAY_CHUNK_SIZE).stream()
                    .map(this::processBatchResultChunk)
                    .toList();
            return sumChunkResultsOrThrow("coordinator.process_batch_results", chunkResults);
        }, "coordinator.process_batch_results");
    }

    private Try<Integer> processBatchResultChunk(List<String> chunk) {
        return Try.of(() -> {
            Integer processed = observeDb("coordinator.process_batch_results", () -> jdbc.execute((Connection connection) ->
                    SqlArrays.withJsonbArray(connection, chunk, resultArray ->
                            queryForInt(
                                    connection,
                                    "SELECT coordinator.process_batch_results(?)::text",
                                    resultArray
                            )
                    ).get()
            ));
            return processed == null ? 0 : processed;
        });
    }

    // ========== Shadow audit ==========

    /**
     * Generates shadow device alerts.
     * coordinator.generate_shadow_alerts()
     */
    public DbResult<List<String>> generateShadowAlerts() {
        return DbResult.of(
                () -> observeDb("coordinator.generate_shadow_alerts", () -> jdbc.queryForList(
                        "SELECT coordinator.generate_shadow_alerts()::text",
                        String.class
                )),
                "coordinator.generate_shadow_alerts"
        );
    }

    // ========== Wireless: Backlog ==========

    public DbResult<Void> saveBacklogEntry(String payloadJson) {
        return DbResult.run(
                () -> observeDb("coordinator.save_backlog_entry",
                        () -> jdbc.update("SELECT coordinator.save_backlog_entry(?::jsonb)", payloadJson)),
                "coordinator.save_backlog_entry"
        );
    }

    public DbResult<String> listPendingBacklog() {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.list_pending_backlog", () -> jdbc.queryForObject(
                    "SELECT coordinator.list_pending_backlog()::text",
                    String.class
            ));
            return blankToNull(result);
        }, "coordinator.list_pending_backlog");
    }

    public DbResult<Void> markBacklogSynced(String dedupeKey) {
        return DbResult.run(
                () -> observeDb("coordinator.mark_backlog_synced",
                        () -> jdbc.update("SELECT coordinator.mark_backlog_synced(?::text)", dedupeKey)),
                "coordinator.mark_backlog_synced"
        );
    }

    public DbResult<String> pruneBacklog() {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.prune_backlog", () -> jdbc.queryForObject(
                    "SELECT coordinator.prune_backlog()::text",
                    String.class
            ));
            return blankToNull(result);
        }, "coordinator.prune_backlog");
    }

    // ========== Wireless: MAC lookup ==========

    public DbResult<String> lookupDeviceByMac(String mac) {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.lookup_device_by_mac", () -> jdbc.queryForObject(
                    "SELECT coordinator.lookup_device_by_mac(?::text)::text",
                    String.class,
                    mac
            ));
            return blankToNull(result);
        }, "coordinator.lookup_device_by_mac");
    }

    // ========== Wireless: Networks ==========

    public DbResult<String> listAuthorizedNetworks() {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.list_authorized_networks", () -> jdbc.queryForObject(
                    "SELECT coordinator.list_authorized_networks()::text",
                    String.class
            ));
            return blankToNull(result);
        }, "coordinator.list_authorized_networks");
    }

    // ========== Wireless: Probe flush ==========

    public DbResult<Void> flushProbeBatch(String probesJson) {
        return DbResult.run(
                () -> observeDb("coordinator.flush_probe_batch",
                        () -> jdbc.update("SELECT coordinator.flush_probe_batch(?::jsonb)", probesJson)),
                "coordinator.flush_probe_batch"
        );
    }

    // ========== Retention and raw payload archive ==========

    public DbResult<List<PayloadArchiveCandidate>> listWirelessPayloadArchiveCandidates() {
        return DbResult.of(
                () -> observeDb("coordinator.list_wireless_payload_archive_candidates", () -> jdbc.query(
                        "SELECT dedupe_key, stream_name, observed_at, payload_sha256, payload_bytes, payload::text AS payload " +
                                "FROM coordinator.list_wireless_payload_archive_candidates(?::integer, ?::integer)",
                        (rs, rowNum) -> new PayloadArchiveCandidate(
                                rs.getString("dedupe_key"),
                                rs.getString("stream_name"),
                                rs.getObject("observed_at", OffsetDateTime.class),
                                rs.getString("payload_sha256"),
                                rs.getLong("payload_bytes"),
                                rs.getString("payload")
                        ),
                        props.wirelessRawPayloadHotDays(),
                        props.wirelessRawArchiveBatchSize()
                )),
                "coordinator.list_wireless_payload_archive_candidates"
        );
    }

    public DbResult<Boolean> recordPayloadArchive(String dedupeKey,
                                                  String payloadSha256,
                                                  String archiveUri,
                                                  long payloadBytes) {
        return DbResult.of(() -> {
            Boolean recorded = observeDb("coordinator.record_payload_archive", () -> jdbc.queryForObject(
                    "SELECT coordinator.record_payload_archive(?::text, ?::text, ?::text, ?::bigint)",
                    Boolean.class,
                    dedupeKey,
                    payloadSha256,
                    archiveUri,
                    payloadBytes
            ));
            return Boolean.TRUE.equals(recorded);
        }, "coordinator.record_payload_archive");
    }

    public DbResult<String> pruneSyncEventRetention() {
        return DbResult.of(() -> {
            String result = observeDb("coordinator.prune_sync_event_retention", () -> jdbc.queryForObject(
                    "SELECT coordinator.prune_sync_event_retention(?::integer, ?::integer, ?::integer)::text",
                    String.class,
                    props.syncEventRowRetentionDays(),
                    props.syncEventTombstoneRetentionDays(),
                    props.retentionPruneBatchSize()
            ));
            return blankToNull(result);
        }, "coordinator.prune_sync_event_retention");
    }

    public DbResult<String> pruneVectorRetention() {
        return DbResult.of(() -> {
            String result = observeDb("vec_prune_retention", () -> jdbc.queryForObject(
                    "SELECT vec_prune_retention()::text",
                    String.class
            ));
            return blankToNull(result);
        }, "vec_prune_retention");
    }

    // ========== Helpers ==========

    private <T> T observeDb(String operation, Supplier<T> supplier) {
        return Observation
                .createNotStarted("db.client.operation", observationRegistry)
                .lowCardinalityKeyValue("db.system", "postgresql")
                .lowCardinalityKeyValue("db.operation", operation)
                .lowCardinalityKeyValue("db.name", "sync")
                .observe(supplier);
    }

    private <T> List<String> extract(List<T> items, Function<T, String> extractor) {
        return items.stream().map(extractor).toList();
    }

    private int sumChunkResultsOrThrow(String operation, List<Try<Integer>> chunkResults) {
        int successfulCount = 0;
        List<Throwable> failures = new ArrayList<>();

        for (Try<Integer> chunkResult : chunkResults) {
            if (chunkResult.isSuccess()) {
                successfulCount += chunkResult.get();
            } else {
                failures.add(chunkResult.getCause());
            }
        }

        if (!failures.isEmpty()) {
            for (int i = 0; i < failures.size(); i++) {
                log.error("event=database_chunk status=failed operation={} failure_index={} successful_count={} error=\"{}\"",
                        operation, i, successfulCount, sanitize(failures.get(i).getMessage()));
            }
            throw new IllegalStateException(
                    "%s failed for %d chunk(s) after %d successful row(s)"
                            .formatted(operation, failures.size(), successfulCount),
                    failures.get(0)
            );
        }

        return successfulCount;
    }

    private static String joinCsv(List<String> items) {
        return items.isEmpty() ? "" : String.join(",", items);
    }

    private int queryForInt(Connection connection, String sql, Array... arrays) throws SQLException {
        return parseIntOrZero(queryForSingleText(connection, sql, arrays), sql);
    }

    private String queryForSingleText(Connection connection, String sql, Array... arrays) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < arrays.length; i++) {
                statement.setArray(i + 1, arrays[i]);
            }
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? resultSet.getString(1) : null;
            }
        }
    }

    private int parseIntOrZero(String result, String operation) {
        if (result == null || result.isBlank()) {
            return 0;
        }
        try {
            return Integer.parseInt(result.trim());
        } catch (NumberFormatException e) {
            log.warn("{} returned non-numeric: {}", operation, result);
            return 0;
        }
    }

    private long parseLongOrZero(String result, String operation) {
        if (result == null || result.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(result.trim());
        } catch (NumberFormatException e) {
            log.warn("{} returned non-numeric: {}", operation, result);
            return 0L;
        }
    }

    private String blankToNull(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }

    // ========== Inner records ==========

    /** Represents a scan request record to be inserted. */
    public record ScanRequestRecord(String requestJson, String payloadJson, String payloadSha256) {}

    public record PayloadArchiveCandidate(
            String dedupeKey,
            String streamName,
            OffsetDateTime observedAt,
            String payloadSha256,
            long payloadBytes,
            String payloadJson
    ) {}
}
