package com.sslproxy.coordinator.service;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SqlFunctionContractTest {

    @Test
    void recordScanRequestBatchSkipsTombstonedWirelessFrameUpserts() throws Exception {
        assertRecordScanRequestBatchTombstoneGuard(readSql("../../sql/functions/022_coordinator_record_scan_request_batch.sql"));
        assertRecordScanRequestBatchTombstoneGuard(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void graphEmbeddingJobsOnlyRequeueWhenGraphIsNewerThanEmbedding() throws Exception {
        assertGraphEmbeddingFreshnessGuard(readSql("../../sql/functions/011_vec_enqueue_embedding_jobs.sql"));
        assertGraphEmbeddingFreshnessGuard(readSql("../../sql/postgres.source.sql"));
    }

    private void assertRecordScanRequestBatchTombstoneGuard(String sql) {
        int functionStart = sql.indexOf("create or replace function coordinator.record_scan_request_batch");
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
        int freshnessGuard = sql.indexOf("keys.source_updated_at > existing.embedded_at", embeddingJoin);

        assertTrue(graphKeys > 0, "expected graph key freshness CTE");
        assertTrue(graphJobs > graphKeys, "expected graph jobs CTE after graph keys");
        assertTrue(embeddingJoin > graphJobs, "graph jobs must compare existing embeddings");
        assertTrue(freshnessGuard > embeddingJoin, "graph jobs must skip already-fresh embeddings");
    }

    private String readSql(String relativePath) throws Exception {
        return Files.readString(Path.of(System.getProperty("user.dir")).resolve(relativePath).normalize());
    }
}
