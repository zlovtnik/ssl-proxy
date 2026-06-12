package com.sslproxy.coordinator.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers(disabledWithoutDocker = true)
class CoordinatorGetNextBatchSqlTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUpSchema() throws Exception {
        try (Connection connection = connection()) {
            execute(connection, "drop table if exists sync_errors");
            execute(connection, "drop table if exists sync_batches");
            execute(connection, "drop table if exists sync_jobs");
            execute(connection, "drop table if exists sync_events");
            execute(connection, "drop table if exists sync_cursors");
            execute(connection, "drop schema if exists coordinator cascade");
            execute(connection, "create schema coordinator");
            execute(connection, """
                    create table sync_cursors (
                      stream_name text primary key,
                      cursor_value text not null,
                      updated_at timestamptz not null default now()
                    )
                    """);
            execute(connection, """
                    create table sync_events (
                      dedupe_key text primary key,
                      stream_name text not null,
                      observed_at timestamptz not null,
                      payload_ref text not null,
                      payload jsonb,
                      payload_sha256 text,
                      status text not null default 'pending',
                      attempt_count integer not null default 0,
                      last_error text,
                      producer text not null default 'unknown',
                      event_kind text,
                      created_at timestamptz not null default now(),
                      updated_at timestamptz not null default now()
                    )
                    """);
            execute(connection, """
                    create table sync_jobs (
                      job_id uuid primary key,
                      stream_name text not null,
                      status text not null,
                      attempt_count integer not null default 0,
                      created_at timestamptz not null default now(),
                      started_at timestamptz,
                      finished_at timestamptz
                    )
                    """);
            execute(connection, """
                    create table sync_batches (
                      batch_id uuid primary key,
                      job_id uuid not null references sync_jobs(job_id),
                      batch_no integer not null,
                      payload_ref text not null,
                      status text not null,
                      row_count integer,
                      checksum text,
                      attempt_count integer not null default 0,
                      last_error text,
                      dedupe_key text not null unique,
                      cursor_start text not null,
                      cursor_end text not null,
                      created_at timestamptz not null default now(),
                      updated_at timestamptz not null default now()
                    )
                    """);
            execute(connection, """
                    create table sync_errors (
                      id bigserial primary key,
                      job_id uuid references sync_jobs(job_id),
                      batch_id uuid references sync_batches(batch_id),
                      error_class text not null,
                      error_text text not null,
                      created_at timestamptz not null default now()
                    )
                    """);
            execute(connection, Files.readString(getNextBatchSql()));
        }
    }

    @Test
    void repairsBlankBatchPayloadRefFromStoredEventPayload() throws Exception {
        try (Connection connection = connection()) {
            insertCursor(connection, "wireless.audit");
            insertJob(connection, "11111111-1111-1111-1111-111111111111", "wireless.audit");
            insertEvent(connection, "dedupe-1", "wireless.audit", "{\"event_type\":\"audit\"}");
            insertBatch(connection,
                    "22222222-2222-2222-2222-222222222222",
                    "11111111-1111-1111-1111-111111111111",
                    "dedupe-1",
                    "");

            String result = queryString(connection,
                    "select coordinator.get_next_batch(array['wireless.audit'])::text");

            assertNotNull(result);
            JsonNode payload = objectMapper.readTree(result);
            String payloadRef = payload.get("payload_ref").asText();
            assertTrue(payloadRef.startsWith("inline://json/"));
            assertEquals("dispatched", queryString(connection,
                    "select status from sync_batches where batch_id = '22222222-2222-2222-2222-222222222222'"));
            assertEquals(payloadRef, queryString(connection,
                    "select payload_ref from sync_batches where batch_id = '22222222-2222-2222-2222-222222222222'"));

            JsonNode decoded = objectMapper.readTree(decodeInlinePayload(payloadRef));
            assertEquals("audit", decoded.get("event_type").asText());
        }
    }

    @Test
    void failsBlankBatchPayloadRefWhenStoredPayloadIsUnavailable() throws Exception {
        try (Connection connection = connection()) {
            insertCursor(connection, "wireless.audit");
            insertJob(connection, "33333333-3333-3333-3333-333333333333", "wireless.audit");
            insertBatch(connection,
                    "44444444-4444-4444-4444-444444444444",
                    "33333333-3333-3333-3333-333333333333",
                    "dedupe-missing-payload",
                    "");

            String result = queryString(connection,
                    "select coordinator.get_next_batch(array['wireless.audit'])::text");

            assertNull(result);
            assertEquals("failed", queryString(connection,
                    "select status from sync_batches where batch_id = '44444444-4444-4444-4444-444444444444'"));
            assertEquals("failed", queryString(connection,
                    "select status from sync_jobs where job_id = '33333333-3333-3333-3333-333333333333'"));
            assertEquals("dispatch_payload_ref_missing", queryString(connection,
                    "select error_class from sync_errors where batch_id = '44444444-4444-4444-4444-444444444444'"));
        }
    }

    private Connection connection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private Path getNextBatchSql() {
        return Path.of(System.getProperty("user.dir"))
                .resolve("../../sql/functions/027_coordinator_get_next_batch.sql")
                .normalize();
    }

    private void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private void insertCursor(Connection connection, String streamName) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into sync_cursors (stream_name, cursor_value) values (?, '0')")) {
            statement.setString(1, streamName);
            statement.executeUpdate();
        }
    }

    private void insertJob(Connection connection, String jobId, String streamName) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into sync_jobs (job_id, stream_name, status) values (?::uuid, ?, 'pending')")) {
            statement.setString(1, jobId);
            statement.setString(2, streamName);
            statement.executeUpdate();
        }
    }

    private void insertEvent(Connection connection, String dedupeKey, String streamName, String payload)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into sync_events (
                  dedupe_key, stream_name, observed_at, payload_ref, payload, status
                ) values (?, ?, now(), '', ?::jsonb, 'batched')
                """)) {
            statement.setString(1, dedupeKey);
            statement.setString(2, streamName);
            statement.setString(3, payload);
            statement.executeUpdate();
        }
    }

    private void insertBatch(Connection connection, String batchId, String jobId, String dedupeKey, String payloadRef)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into sync_batches (
                  batch_id, job_id, batch_no, payload_ref, status, row_count,
                  attempt_count, dedupe_key, cursor_start, cursor_end
                ) values (?::uuid, ?::uuid, 0, ?, 'pending', 1, 0, ?, '0', '1')
                """)) {
            statement.setString(1, batchId);
            statement.setString(2, jobId);
            statement.setString(3, payloadRef);
            statement.setString(4, dedupeKey);
            statement.executeUpdate();
        }
    }

    private String queryString(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            if (!resultSet.next()) {
                return null;
            }
            String value = resultSet.getString(1);
            return resultSet.wasNull() ? null : value;
        }
    }

    private String decodeInlinePayload(String payloadRef) {
        String encoded = payloadRef.substring("inline://json/".length());
        int remainder = encoded.length() % 4;
        if (remainder != 0) {
            encoded = encoded + "=".repeat(4 - remainder);
        }
        byte[] decoded = Base64.getUrlDecoder().decode(encoded);
        return new String(decoded, StandardCharsets.UTF_8);
    }
}
