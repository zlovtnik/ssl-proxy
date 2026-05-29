package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Wraps all stored procedure calls to the coordinator schema.
 * Corresponds to zig files: db.zig, db_sync.zig, db_wireless.zig
 */
@Service
public class DatabaseService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseService.class);

    private final JdbcTemplate jdbc;
    private final CoordinatorProperties props;

    public DatabaseService(JdbcTemplate jdbc, CoordinatorProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    // ========== Connectivity ==========

    /** Quick connectivity check. */
    public void checkConnectivity() {
        jdbc.queryForObject("SELECT 1", Integer.class);
    }

    // ========== Cursor management ==========

    /**
     * Ensures a cursor for the given stream name exists.
     * Returns the cursor value.
     */
    public String ensureCursor(String streamName) {
        return jdbc.queryForObject(
                "SELECT coordinator.ensure_cursor(?::text)::text",
                String.class,
                streamName
        );
    }

    /**
     * Ensures cursors for all configured streams.
     * Returns the cursor for the primary stream.
     */
    public String ensureAllCursors() {
        String primaryCursor = null;
        for (String rawName : props.getStreamNames().split(",")) {
            String name = rawName.trim();
            if (name.isEmpty()) continue;
            String cursor = ensureCursor(name);
            if (name.equals(props.getStreamName())) {
                primaryCursor = cursor;
            }
        }
        if (primaryCursor == null) {
            throw new RuntimeException("Cursor not found for primary stream: " + props.getStreamName());
        }
        return primaryCursor;
    }

    // ========== Ingest ledger ==========

    /**
     * Returns the count of pending ledger entries.
     * coordinator.pending_ledger_count()
     */
    public long pendingLedgerCount() {
        return Optional.ofNullable(
                jdbc.queryForObject(
                        "SELECT coordinator.pending_ledger_count()::text",
                        String.class
                )
        ).map(Long::parseLong).orElse(0L);
    }

    /**
     * Processes the ingest ledger. Returns number of events processed.
     * coordinator.process_ingest_ledger()
     */
    public long processIngestLedger() {
        String streamNames = normalizeCsv(props.getStreamNames());
        String oracleStreamNames = normalizeCsv(props.getOracleStreamNames());
        String result = jdbc.queryForObject(
                "SELECT coordinator.process_ingest_ledger(" +
                        "string_to_array(?::text, ','), " +
                        "string_to_array(?::text, ','), " +
                        "?::integer, ?::integer, ?::integer)::text",
                String.class,
                streamNames, oracleStreamNames,
                props.getScanMaxAttempts(),
                props.getScanRetryBackoffSeconds(),
                props.getIngestBatchSize()
        );
        if (result == null || result.isEmpty()) return 0;
        try {
            return Long.parseLong(result.trim());
        } catch (NumberFormatException e) {
            log.warn("processIngestLedger returned non-numeric: {}", result);
            return 0;
        }
    }

    // ========== Scan request recording ==========

    /**
     * Records scan request batches.
     * coordinator.record_scan_request_batch()
     */
    public int recordScanRequests(List<ScanRequestRecord> records) {
        if (records.isEmpty()) return 0;

        int totalRecorded = 0;
        int chunkSize = 500;

        for (int start = 0; start < records.size(); start += chunkSize) {
            int end = Math.min(start + chunkSize, records.size());
            List<ScanRequestRecord> chunk = records.subList(start, end);

            String requestJsonArray = toJsonbArray(chunk, r -> r.requestJson);
            String payloadJsonArray = toJsonbArray(chunk, r -> r.payloadJson);
            String shaArray = toTextArray(chunk, r -> r.payloadSha256);
            String streamNames = normalizeCsv(props.getStreamNames());

            String recorded = jdbc.queryForObject(
                    "SELECT coordinator.record_scan_request_batch(" +
                            "?::jsonb[], ?::jsonb[], ?::text[], " +
                            "string_to_array(?::text, ','))::text",
                    String.class,
                    requestJsonArray, payloadJsonArray, shaArray, streamNames
            );
            if (recorded != null && !recorded.isEmpty()) {
                totalRecorded += Integer.parseInt(recorded.trim());
            }
        }
        return totalRecorded;
    }

    // ========== Batch dispatch ==========

    /**
     * Gets the next batch to dispatch. Returns the JSON payload or empty.
     * coordinator.get_next_batch()
     */
    public Optional<String> getNextBatch() {
        String oracleStreamNames = normalizeCsv(props.getOracleStreamNames());
        String result = jdbc.queryForObject(
                "SELECT coordinator.get_next_batch(string_to_array(?::text, ','))::text",
                String.class,
                oracleStreamNames
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    /**
     * Recovers stale dispatched batches.
     * coordinator.recover_stale_dispatched_batches()
     */
    public int recoverStaleDispatchedBatches() {
        String oracleStreamNames = normalizeCsv(props.getOracleStreamNames());
        String result = jdbc.queryForObject(
                "SELECT coordinator.recover_stale_dispatched_batches(" +
                        "string_to_array(?::text, ','), " +
                        "?::integer, ?::integer)::text",
                String.class,
                oracleStreamNames,
                props.getBatchDispatchLeaseSeconds(),
                props.getBatchMaxAttempts()
        );
        if (result == null || result.isEmpty()) return 0;
        return Integer.parseInt(result.trim());
    }

    /**
     * Marks a batch dispatch as failed.
     * coordinator.mark_batch_dispatch_failed()
     */
    public Optional<String> markBatchDispatchFailed(String loadJson, String errorText) {
        String result = jdbc.queryForObject(
                "SELECT coordinator.mark_batch_dispatch_failed(?::jsonb, ?::text, ?::integer)::text",
                String.class,
                loadJson, errorText, props.getBatchMaxAttempts()
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    /**
     * Releases a batch dispatch with an error.
     * coordinator.release_batch_dispatch()
     */
    public Optional<String> releaseBatchDispatch(String loadJson, String errorText) {
        String result = jdbc.queryForObject(
                "SELECT coordinator.release_batch_dispatch(?::jsonb, ?::text)::text",
                String.class,
                loadJson, errorText
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    // ========== Results ==========

    /**
     * Processes batch results. Returns the number of results processed.
     * coordinator.process_batch_results()
     */
    public int processBatchResults(List<String> resultJsons) {
        if (resultJsons.isEmpty()) return 0;

        int total = 0;
        int chunkSize = 500;

        for (int start = 0; start < resultJsons.size(); start += chunkSize) {
            int end = Math.min(start + chunkSize, resultJsons.size());
            List<String> chunk = resultJsons.subList(start, end);
            String resultArray = toJsonbArray(chunk);

            String result = jdbc.queryForObject(
                    "SELECT coordinator.process_batch_results(?::jsonb[])::text",
                    String.class,
                    resultArray
            );
            if (result != null && !result.isEmpty()) {
                total += Integer.parseInt(result.trim());
            }
        }
        return total;
    }

    // ========== Shadow audit ==========

    /**
     * Generates shadow device alerts.
     * coordinator.generate_shadow_alerts()
     */
    public Optional<String> generateShadowAlerts() {
        String result = jdbc.queryForObject(
                "SELECT coordinator.generate_shadow_alerts()::text",
                String.class
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    // ========== Wireless: Backlog ==========

    public void saveBacklogEntry(String payloadJson) {
        jdbc.update("SELECT coordinator.save_backlog_entry(?::jsonb)", payloadJson);
    }

    public Optional<String> listPendingBacklog() {
        String result = jdbc.queryForObject(
                "SELECT coordinator.list_pending_backlog()::text",
                String.class
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    public void markBacklogSynced(String dedupeKey) {
        jdbc.update("SELECT coordinator.mark_backlog_synced(?::text)", dedupeKey);
    }

    public Optional<String> pruneBacklog() {
        String result = jdbc.queryForObject(
                "SELECT coordinator.prune_backlog()::text",
                String.class
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    // ========== Wireless: MAC lookup ==========

    public Optional<String> lookupDeviceByMac(String mac) {
        String result = jdbc.queryForObject(
                "SELECT coordinator.lookup_device_by_mac(?::text)::text",
                String.class,
                mac
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    // ========== Wireless: Networks ==========

    public Optional<String> listAuthorizedNetworks() {
        String result = jdbc.queryForObject(
                "SELECT coordinator.list_authorized_networks()::text",
                String.class
        );
        return Optional.ofNullable(result).filter(s -> !s.isEmpty());
    }

    // ========== Wireless: Probe flush ==========

    public void flushProbeBatch(String probesJson) {
        jdbc.update("SELECT coordinator.flush_probe_batch(?::jsonb)", probesJson);
    }

    // ========== Helpers ==========

    /**
     * Normalizes a CSV string (trims whitespace, removes empties).
     */
    public String normalizeCsv(String csv) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String part : csv.split(",")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            if (!first) sb.append(',');
            sb.append(trimmed);
            first = false;
        }
        return sb.toString();
    }

    /**
     * Builds a Postgres text array literal: {a,b,c}
     */
    private String toTextArray(List<ScanRequestRecord> records, java.util.function.Function<ScanRequestRecord, String> extractor) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < records.size(); i++) {
            if (i > 0) sb.append(',');
            String val = extractor.apply(records.get(i));
            if (val == null) {
                sb.append("NULL");
            } else {
                sb.append(escapeSqlLiteral(val));
            }
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Builds a Postgres jsonb[] SQL array literal.
     */
    private String toJsonbArray(List<ScanRequestRecord> records, java.util.function.Function<ScanRequestRecord, String> extractor) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < records.size(); i++) {
            if (i > 0) sb.append(',');
            String val = extractor.apply(records.get(i));
            if (val == null) {
                sb.append("null");
            } else {
                sb.append(escapeSqlLiteral(val));
            }
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Builds a Postgres jsonb[] SQL array literal from a list of JSON strings.
     */
    private String toJsonbArray(List<String> items) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            if (items.get(i) == null) {
                sb.append("null");
            } else {
                sb.append(escapeSqlLiteral(items.get(i)));
            }
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Escapes a string for use as a Postgres literal inside array syntax.
     */
    private String escapeSqlLiteral(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    // ========== Inner class ==========

    /** Represents a scan request record to be inserted. */
    public static class ScanRequestRecord {
        private final String requestJson;
        private final String payloadJson;
        private final String payloadSha256;

        public ScanRequestRecord(String requestJson, String payloadJson, String payloadSha256) {
            this.requestJson = requestJson;
            this.payloadJson = payloadJson;
            this.payloadSha256 = payloadSha256;
        }

        public String getRequestJson() { return requestJson; }
        public String getPayloadJson() { return payloadJson; }
        public String getPayloadSha256() { return payloadSha256; }
    }
}
