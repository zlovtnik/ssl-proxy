package com.sslproxy.coordinator.service;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqlFunctionContractTest {

    @Test
    void recordScanRequestBatchSkipsTombstonedWirelessFrameUpserts() throws Exception {
        assertRecordScanRequestBatchTombstoneGuard(readSql("../../sql/functions/054_coordinator_record_scan_request_batch_deduplicate.sql"));
        assertRecordScanRequestBatchTombstoneGuard(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void recordScanRequestBatchSafelyFiltersInvalidObservedAt() throws Exception {
        assertRecordScanRequestBatchSafeObservedAt(readSql("../../sql/functions/022_coordinator_record_scan_request_batch.sql"));
        assertRecordScanRequestBatchSafeObservedAt(readSql("../../sql/functions/053_coordinator_record_scan_request_batch_tombstone_frames.sql"));
        assertRecordScanRequestBatchSafeObservedAt(readSql("../../sql/functions/054_coordinator_record_scan_request_batch_deduplicate.sql"));
        assertRecordScanRequestBatchSafeObservedAt(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void recordScanRequestBatchDeduplicatesConflictingRowsBeforeUpsert() throws Exception {
        assertRecordScanRequestBatchDeduplicates(readSql("../../sql/functions/054_coordinator_record_scan_request_batch_deduplicate.sql"));
        assertRecordScanRequestBatchDeduplicates(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void expiredEmbeddingLeaseReleaseDoesNotRequeueTerminalAttempts() throws Exception {
        assertExpiredLeaseReleaseCapsAttempts(readSql("../../sql/functions/016_vec_release_expired_leases.sql"));
        assertExpiredLeaseReleaseCapsAttempts(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void wirelessFramesUsesSoftSyncEventReference() throws Exception {
        assertWirelessFramesSoftReference(readSql("../../sql/tables/003_wireless_frames.sql"));
        assertWirelessFramesSoftReference(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void searchQueryAndFeedbackSchemaObjectsAreSplit() throws Exception {
        String bootstrap = readSql("../../sql/postgres.sql");
        assertTrue(bootstrap.contains("\\ir tables/028_search_queries.sql"));
        assertTrue(bootstrap.contains("\\ir tables/028a_search_feedback.sql"));

        String queries = readSql("../../sql/tables/028_search_queries.sql");
        String feedback = readSql("../../sql/tables/028a_search_feedback.sql");

        assertTrue(queries.contains("-- object: search_queries"));
        assertTrue(queries.contains("create table if not exists search_queries"));
        assertFalse(queries.contains("create table if not exists search_feedback"));
        assertTrue(feedback.contains("-- object: search_feedback"));
        assertTrue(feedback.contains("-- depends_on: search_queries"));
        assertTrue(feedback.contains("create table if not exists search_feedback"));
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
    void postgresBootstrapIncludesBatchIngestReplacementMigrations() throws Exception {
        String sql = readSql("../../sql/postgres.sql");

        assertTrue(sql.contains("\\ir functions/053_coordinator_record_scan_request_batch_tombstone_frames.sql"));
        assertTrue(sql.contains("\\ir functions/054_coordinator_record_scan_request_batch_deduplicate.sql"));
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
    void eventEmbeddingCursorAdvancesAfterScannedKeys() throws Exception {
        assertEventEmbeddingCursorAdvanceGuard(readSql("../../sql/functions/011_vec_enqueue_embedding_jobs.sql"));
        assertEventEmbeddingCursorAdvanceGuard(readSql("../../sql/postgres.source.sql"));
    }

    @Test
    void similarityPairsAcceptsTimingThresholdParameter() throws Exception {
        assertSimilarityPairsTimingThreshold(readSql("../../sql/functions/014_vec_materialize_similarity_pairs.sql"));
        assertSimilarityPairsTimingThreshold(readSql("../../sql/postgres.source.sql"));
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

    private void assertRecordScanRequestBatchSafeObservedAt(String sql) {
        int functionStart = sql.lastIndexOf("create or replace function coordinator.record_scan_request_batch");
        int typed = sql.indexOf("typed as", functionStart);
        int safeCast = sql.indexOf("coordinator.safe_timestamptz(incoming.observed_at_text) as observed_at", typed);
        int valid = sql.indexOf("valid as", safeCast);
        int validGuard = sql.indexOf("and typed.observed_at is not null", valid);
        int insertSelect = sql.indexOf("select dedupe_key,\n           stream_name,\n           observed_at,", validGuard);
        int frameUpsert = sql.indexOf("perform coordinator.upsert_wireless_frame_from_payload", insertSelect);
        int frameGuard = sql.indexOf("coordinator.safe_timestamptz(raw.request->>'observed_at') is not null", frameUpsert);
        int unsafeCast = sql.indexOf("observed_at_text::timestamptz", functionStart);

        assertTrue(functionStart >= 0, "expected batch ingest function");
        assertTrue(typed > functionStart, "batch ingest must parse observed_at before insert");
        assertTrue(safeCast > typed, "batch ingest must use safe timestamptz parsing");
        assertTrue(valid > safeCast, "valid rows must be filtered after timestamp parsing");
        assertTrue(validGuard > valid, "invalid observed_at rows must be skipped");
        assertTrue(insertSelect > validGuard, "insert must use the parsed timestamp");
        assertTrue(frameGuard > frameUpsert, "wireless frame upsert must skip invalid observed_at rows");
        assertFalse(unsafeCast > functionStart, "batch ingest must not cast observed_at_text directly");
    }

    private void assertRecordScanRequestBatchDeduplicates(String sql) {
        int functionStart = sql.lastIndexOf("create or replace function coordinator.record_scan_request_batch");
        int ordinality = sql.indexOf("with ordinality as raw(request, payload, payload_sha256, input_ordinality)", functionStart);
        int valid = sql.indexOf("valid as", ordinality);
        int deduplicated = sql.indexOf("deduplicated as", valid);
        int distinctKey = sql.indexOf("select distinct on (valid.dedupe_key) valid.*", deduplicated);
        int lastInputWins = sql.indexOf("order by valid.dedupe_key, valid.input_ordinality desc", distinctKey);
        int insertSource = sql.indexOf("from deduplicated", lastInputWins);
        int frameUpsert = sql.indexOf("perform coordinator.upsert_wireless_frame_from_payload", insertSource);
        int frameDistinctKey = sql.indexOf("select distinct on (raw.dedupe_key)", frameUpsert);
        int frameLastInputWins = sql.indexOf("order by raw.dedupe_key, raw.input_ordinality desc", frameDistinctKey);

        assertTrue(functionStart >= 0, "expected batch ingest function");
        assertTrue(ordinality > functionStart, "batch ingest must retain input order");
        assertTrue(valid > ordinality, "batch ingest must validate rows before deduplication");
        assertTrue(deduplicated > valid, "batch ingest must deduplicate valid rows");
        assertTrue(distinctKey > deduplicated, "batch ingest must emit one row per dedupe key");
        assertTrue(lastInputWins > distinctKey, "the last valid input must win duplicate conflicts");
        assertTrue(insertSource > lastInputWins, "sync_events upsert must consume deduplicated rows");
        assertTrue(frameDistinctKey > frameUpsert, "wireless frame upserts must also be deduplicated");
        assertTrue(frameLastInputWins > frameDistinctKey, "wireless frame deduplication must match batch ordering");
    }

    private void assertExpiredLeaseReleaseCapsAttempts(String sql) {
        int functionStart = sql.indexOf("create or replace function vec_release_expired_leases");
        int terminalStatus = sql.indexOf("when attempts >= max_attempts then 'failed'", functionStart);
        int retryStatus = sql.indexOf("else 'pending'", terminalStatus);
        int terminalError = sql.indexOf("when attempts >= max_attempts then 'lease expired after max attempts'", retryStatus);

        assertTrue(functionStart >= 0, "expected expired lease release function");
        assertTrue(terminalStatus > functionStart, "expired terminal leases must become failed");
        assertTrue(retryStatus > terminalStatus, "expired retryable leases must return to pending");
        assertTrue(terminalError > retryStatus, "terminal lease failures need an explicit error");
    }

    private void assertWirelessFramesSoftReference(String sql) {
        int tableStart = sql.indexOf("create table if not exists wireless_frames");
        int tableEnd = sql.indexOf(");", tableStart);
        int fk = sql.indexOf("references sync_events(dedupe_key)", tableStart);
        int dropFk = sql.indexOf("drop constraint if exists wireless_frames_dedupe_key_fkey", tableEnd);

        assertTrue(tableStart >= 0, "expected wireless_frames table");
        assertTrue(tableEnd > tableStart, "expected wireless_frames table end");
        assertFalse(fk > tableStart && fk < tableEnd, "wireless_frames must not enforce sync_events FK");
        assertTrue(dropFk > tableEnd, "existing wireless_frames FK must be dropped idempotently");
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
        int cursorEventKeys = sql.indexOf("cursor_event_keys as", cursorLoad);
        int keySource = sql.indexOf("from sync_events e", cursorEventKeys);
        int frameJoin = sql.indexOf("left join wireless_frames frame on frame.dedupe_key = e.dedupe_key", keySource);
        int effectiveTimestamp = sql.indexOf("greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) as event_updated_at", cursorEventKeys);
        int cursorGuard = sql.indexOf("greatest(e.updated_at, coalesce(frame.updated_at, e.updated_at)) > v_event_cursor", frameJoin);
        int keyOrder = sql.indexOf("order by cursor_updated_at, e.dedupe_key", cursorGuard);
        int alertEventKeys = sql.indexOf("alert_event_keys as", keyOrder);
        int alertSource = sql.indexOf("from vec_alerts alert", alertEventKeys);
        int alertJoin = sql.indexOf("join sync_events e", alertSource);
        int alertCursorGuard = sql.indexOf("alert.created_at > v_event_cursor", alertJoin);
        int alertMatch = sql.indexOf("alert.metadata->>'dedupe_key' = e.dedupe_key", alertCursorGuard);
        int eventKeys = sql.indexOf("event_keys as", alertMatch);
        int cursorUnion = sql.indexOf("select * from cursor_event_keys", eventKeys);
        int alertUnion = sql.indexOf("select * from alert_event_keys", cursorUnion);
        int eventJobs = sql.indexOf("event_jobs as", alertUnion);
        int expandedJoin = sql.indexOf("join sync_events_expanded source", eventJobs);

        assertTrue(functionStart >= 0, "expected enqueue function");
        assertTrue(cursorLoad > functionStart, "event cursor must be loaded before event jobs");
        assertTrue(cursorEventKeys > cursorLoad, "event jobs must start from a cursor-filtered key CTE");
        assertTrue(keySource > cursorEventKeys, "event key seed must read sync_events directly");
        assertTrue(frameJoin > keySource, "event key seed must include wireless frame freshness");
        assertTrue(effectiveTimestamp > cursorEventKeys, "event key seed must track expanded event freshness");
        assertTrue(cursorGuard > frameJoin, "event key seed must use the effective embedding cursor");
        assertTrue(keyOrder > cursorGuard, "event key seed must preserve updated_at index order");
        assertTrue(alertEventKeys > keyOrder, "alert-triggered event keys must follow cursor keys");
        assertTrue(alertSource > alertEventKeys, "alert key seed must read vec_alerts");
        assertTrue(alertJoin > alertSource, "alert key seed must match wireless audit events");
        assertTrue(alertCursorGuard > alertJoin, "alert key seed must only consume new alerts");
        assertTrue(alertMatch > alertCursorGuard, "alert key seed must match event identifiers");
        assertTrue(eventKeys > alertMatch, "event keys must combine cursor and alert seeds");
        assertTrue(cursorUnion > eventKeys, "event keys must include cursor-derived candidates");
        assertTrue(alertUnion > cursorUnion, "event keys must include alert-derived candidates");
        assertTrue(eventJobs > alertUnion, "event jobs must run after key seeding");
        assertTrue(expandedJoin > eventJobs, "expanded event view should only be joined after key seeding");
    }

    private void assertEventEmbeddingCursorAdvanceGuard(String sql) {
        int functionStart = sql.indexOf("create or replace function vec_enqueue_embedding_jobs");
        assertTrue(functionStart >= 0, "expected enqueue function");

        int returningMarker = sql.indexOf("returning source_table, source_key, embedding_kind", functionStart);
        assertTrue(returningMarker > functionStart, "expected embedding insert returning marker");

        int insertedCount = sql.indexOf("(select count(*) from inserted)", returningMarker);
        int eventCount = sql.indexOf("(select count(*) from event_keys)", insertedCount + 1);
        int eventCursorMax = sql.indexOf("(select max(cursor_updated_at) from event_keys)", eventCount);
        int intoCounts = sql.indexOf("into v_count, v_event_count, v_event_cursor_next", eventCursorMax);
        int cursorGuard = sql.indexOf("if v_event_count > 0 and v_event_cursor_next is not null then", intoCounts);
        int cursorAdvance = sql.indexOf("insert into sync_cursors (stream_name, cursor_value, updated_at)", cursorGuard);
        int guardEnd = sql.indexOf("end if;", cursorAdvance);
        int finishJob = sql.indexOf("perform vec_finish_job('vec_enqueue_embedding_jobs')", guardEnd);

        assertTrue(insertedCount > functionStart, "expected inserted job count");
        assertTrue(eventCount > insertedCount, "embedding cursor must count scanned event keys");
        assertTrue(eventCursorMax > eventCount, "embedding cursor must use scanned key freshness");
        assertTrue(intoCounts > eventCursorMax, "embedding cursor must store scanned key aggregates");
        assertTrue(cursorGuard > intoCounts, "embedding cursor must be guarded by scanned event keys");
        assertTrue(cursorAdvance > cursorGuard, "embedding cursor update must be inside the guard");
        assertTrue(guardEnd > cursorAdvance, "cursor guard must close after the cursor update");
        assertTrue(finishJob > guardEnd, "job completion must run after the cursor guard");
    }

    private void assertSimilarityPairsTimingThreshold(String sql) {
        int functionStart = sql.indexOf("create or replace function vec_materialize_similarity_pairs");
        int sequenceThreshold = sql.indexOf("p_sequence_similarity_threshold double precision default 0.10", functionStart);
        int timingThreshold = sql.indexOf("p_timing_similarity_threshold double precision default 0.05", sequenceThreshold);
        int timingPair = sql.indexOf("'timing_timing', p_model, 'timing_profile'", timingThreshold);
        int timingGuard = sql.indexOf("neighbor.cosine_distance <= p_timing_similarity_threshold", timingThreshold);

        assertTrue(functionStart >= 0, "expected similarity pair function");
        assertTrue(sequenceThreshold > functionStart, "expected sequence threshold parameter");
        assertTrue(timingThreshold > sequenceThreshold, "timing threshold must follow sequence threshold");
        assertTrue(timingPair > timingThreshold, "timing pair materialization must be present");
        assertTrue(timingGuard > timingThreshold, "timing pair threshold must use the timing parameter");
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
