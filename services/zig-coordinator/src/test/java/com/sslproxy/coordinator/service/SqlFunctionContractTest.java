package com.sslproxy.coordinator.service;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SqlFunctionContractTest {

    @Test
    void recordScanRequestBatchSkipsTombstonedWirelessFrameUpserts() throws Exception {
        assertRecordScanRequestBatchTombstoneGuard(readSql("../../sql/functions/053_coordinator_record_scan_request_batch_tombstone_frames.sql"));
        assertRecordScanRequestBatchTombstoneGuard(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void recordScanRequestBatchBaseMigrationKeepsOriginalFrameUpsert() throws Exception {
        String sql = readSql("../../sql/functions/022_coordinator_record_scan_request_batch.sql");
        int functionStart = sql.indexOf("create or replace function coordinator.record_scan_request_batch");
        int frameUpsert = sql.indexOf("perform coordinator.upsert_wireless_frame_from_payload", functionStart);
        int tombstoneJoinAfterFrameUpsert = sql.indexOf("left join sync_event_tombstones tombstone", frameUpsert);

        assertTrue(frameUpsert > functionStart, "expected original wireless frame upsert");
        assertTrue(tombstoneJoinAfterFrameUpsert < 0, "base migration should not contain replacement frame tombstone guard");
    }

    @Test
    void postgresBootstrapIncludesTombstoneFrameReplacementMigration() throws Exception {
        String sql = readSql("../../sql/postgres.sql");

        assertTrue(sql.contains("\\ir functions/053_coordinator_record_scan_request_batch_tombstone_frames.sql"));
    }

    @Test
    void graphEmbeddingJobsOnlyRequeueWhenGraphIsNewerThanCompletedJob() throws Exception {
        assertGraphEmbeddingFreshnessGuard(readSql("../../sql/functions/011_vec_enqueue_embedding_jobs.sql"));
        assertGraphEmbeddingFreshnessGuard(readSql("../../sql/postgres.source.sql"));
    }

    private void assertRecordScanRequestBatchTombstoneGuard(String sql) {
        int functionStart = sql.lastIndexOf("create or replace function coordinator.record_scan_request_batch");
        int frameUpsert = sql.indexOf("perform coordinator.upsert_wireless_frame_from_payload", functionStart);
        int tombstoneJoin = sql.indexOf("left join sync_event_tombstones tombstone", frameUpsert);
        int tombstoneFilter = sql.indexOf("and tombstone.dedupe_key is null", frameUpsert);

        assertTrue(functionStart >= 0, "expected batch ingest function");
        assertTrue(frameUpsert > functionStart, "expected wireless frame upsert call");
        assertTrue(tombstoneJoin > frameUpsert, "frame upsert source must join tombstones");
        assertTrue(tombstoneFilter > tombstoneJoin, "frame upsert source must skip live tombstones");
    }

    private void assertGraphEmbeddingFreshnessGuard(String sql) {
        int graphKeys = sql.indexOf("graph_keys as");
        int graphJobs = sql.indexOf("graph_jobs as", graphKeys);
        int embeddingJoin = sql.indexOf("left join vec_embeddings existing", graphJobs);
        int jobJoin = sql.indexOf("left join vec_embedding_jobs existing_job", embeddingJoin);
        int freshnessGuard = sql.indexOf("keys.source_updated_at > coalesce(existing_job.completed_at, existing.embedded_at)", jobJoin);

        assertTrue(graphKeys > 0, "expected graph key freshness CTE");
        assertTrue(graphJobs > graphKeys, "expected graph jobs CTE after graph keys");
        assertTrue(embeddingJoin > graphJobs, "graph jobs must compare existing embeddings");
        assertTrue(jobJoin > embeddingJoin, "graph jobs must compare completed embedding jobs");
        assertTrue(freshnessGuard > jobJoin, "graph jobs must skip already-processed embeddings");
    }

    private String readSql(String relativePath) throws Exception {
        return Files.readString(Path.of(System.getProperty("user.dir")).resolve(relativePath).normalize());
    }
}
