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

        assertTrue(functionStart >= 0, "expected base batch ingest function");
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

    @Test
    void eventEmbeddingJobsUseCursorKeySeedBeforeExpandedJoin() throws Exception {
        assertEventEmbeddingCursorSeed(readSql("../../sql/functions/011_vec_enqueue_embedding_jobs.sql"));
        assertEventEmbeddingCursorSeed(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void eventEmbeddingCursorOnlyAdvancesAfterInsertedJobs() throws Exception {
        assertEventEmbeddingCursorAdvanceGuard(readSql("../../sql/functions/011_vec_enqueue_embedding_jobs.sql"));
        assertEventEmbeddingCursorAdvanceGuard(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void frameSequencesBoundTokenTextToConstraint() throws Exception {
        assertFrameSequenceTokenCap(readSql("../../sql/functions/008_vec_build_frame_sequences.sql"));
        assertFrameSequenceTokenCap(readSql("../../sql/postgres.source.sql"));
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

    private void assertEventEmbeddingCursorSeed(String sql) {
        int functionStart = sql.indexOf("create or replace function vec_enqueue_embedding_jobs");
        int cursorLoad = sql.indexOf("into v_event_cursor", functionStart);
        int eventKeys = sql.indexOf("event_keys as", cursorLoad);
        int keySource = sql.indexOf("from sync_events e", eventKeys);
        int frameJoin = sql.indexOf("left join wireless_frames frame on frame.dedupe_key = e.dedupe_key", keySource);
        int effectiveTimestamp = sql.indexOf("greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) as event_updated_at", eventKeys);
        int cursorGuard = sql.indexOf("greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) > v_event_cursor", frameJoin);
        int keyOrder = sql.indexOf("order by event_updated_at, e.dedupe_key", cursorGuard);
        int eventJobs = sql.indexOf("event_jobs as", keyOrder);
        int expandedJoin = sql.indexOf("join sync_events_expanded source", eventJobs);

        assertTrue(functionStart >= 0, "expected enqueue function");
        assertTrue(cursorLoad > functionStart, "event cursor must be loaded before event jobs");
        assertTrue(eventKeys > cursorLoad, "event jobs must start from a cursor-filtered key CTE");
        assertTrue(keySource > eventKeys, "event key seed must read sync_events directly");
        assertTrue(frameJoin > keySource, "event key seed must include wireless frame freshness");
        assertTrue(effectiveTimestamp > eventKeys, "event key seed must track expanded event freshness");
        assertTrue(cursorGuard > frameJoin, "event key seed must use the effective embedding cursor");
        assertTrue(keyOrder > cursorGuard, "event key seed must preserve updated_at index order");
        assertTrue(eventJobs > keyOrder, "event jobs must run after key seeding");
        assertTrue(expandedJoin > eventJobs, "expanded event view should only be joined after key seeding");
    }

    private void assertEventEmbeddingCursorAdvanceGuard(String sql) {
        int functionStart = sql.indexOf("create or replace function vec_enqueue_embedding_jobs");
        int insertedCount = sql.indexOf("count(*)", sql.indexOf("returning source_table, source_key, embedding_kind", functionStart));
        int eventCount = sql.indexOf("count(*) filter", insertedCount + 1);
        int eventCursorMax = sql.indexOf("max(keys.event_updated_at) filter", eventCount);
        int intoCounts = sql.indexOf("into v_count, v_event_count, v_event_cursor_next", eventCursorMax);
        int eventSourceGuard = sql.indexOf("inserted.source_table = 'sync_events'", eventCount);
        int eventKindGuard = sql.indexOf("inserted.embedding_kind = 'event'", eventSourceGuard);
        int cursorGuard = sql.indexOf("if v_event_count > 0 and v_event_cursor_next is not null then", eventKindGuard);
        int cursorAdvance = sql.indexOf("insert into sync_cursors (stream_name, cursor_value, updated_at)", cursorGuard);
        int guardEnd = sql.indexOf("end if;", cursorAdvance);
        int finishJob = sql.indexOf("perform vec_finish_job('vec_enqueue_embedding_jobs')", guardEnd);

        assertTrue(functionStart >= 0, "expected enqueue function");
        assertTrue(insertedCount > functionStart, "expected inserted job count");
        assertTrue(eventCount > insertedCount, "embedding cursor must compute event-only inserted jobs");
        assertTrue(eventCursorMax > eventCount, "embedding cursor must use event-only max freshness");
        assertTrue(intoCounts > eventCursorMax, "embedding cursor must store event-only aggregates");
        assertTrue(eventSourceGuard > eventCount, "embedding cursor must ignore non-event sources");
        assertTrue(eventKindGuard > eventSourceGuard, "embedding cursor must ignore non-event embedding kinds");
        assertTrue(cursorGuard > eventKindGuard, "embedding cursor must be guarded by inserted event jobs");
        assertTrue(cursorAdvance > cursorGuard, "embedding cursor update must be inside the guard");
        assertTrue(guardEnd > cursorAdvance, "cursor guard must close after the cursor update");
        assertTrue(finishJob > guardEnd, "job completion must run after the cursor guard");
    }

    private void assertFrameSequenceTokenCap(String sql) {
        int functionStart = sql.indexOf("create or replace function vec_build_frame_sequences");
        int prepared = sql.indexOf("prepared as", functionStart);
        int sequenceAggregate = sql.indexOf("upper(regexp_replace(frame_subtype_value, '-', '_', 'g'))", prepared);
        int sequenceLimit = sql.indexOf("65535", sequenceAggregate);
        int sequenceAlias = sql.indexOf("as sequence_tokens", sequenceLimit);
        int semanticAggregate = sql.indexOf("string_agg(semantic_token, ' ' order by observed_at)", sequenceAlias);
        int semanticLimit = sql.indexOf("65535", semanticAggregate);
        int semanticAlias = sql.indexOf("as semantic_tokens", semanticLimit);

        assertTrue(functionStart >= 0, "expected frame sequence builder");
        assertTrue(prepared > functionStart, "frame sequence builder must prepare token text before insert");
        assertTrue(sequenceAggregate > prepared, "sequence token aggregate must exist");
        assertTrue(sequenceLimit > sequenceAggregate, "sequence token aggregate must be capped below the check constraint");
        assertTrue(sequenceAlias > sequenceLimit, "sequence token cap must apply to inserted sequence_tokens");
        assertTrue(semanticAggregate > sequenceAlias, "semantic token aggregate must exist");
        assertTrue(semanticLimit > semanticAggregate, "semantic token aggregate should use the same cap");
        assertTrue(semanticAlias > semanticLimit, "semantic token cap must apply to inserted semantic_tokens");
    }

    private String readSql(String relativePath) throws Exception {
        return Files.readString(Path.of(System.getProperty("user.dir")).resolve(relativePath).normalize());
    }
}
