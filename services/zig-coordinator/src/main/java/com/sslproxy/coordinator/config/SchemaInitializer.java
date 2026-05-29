package com.sslproxy.coordinator.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@Component
public class SchemaInitializer implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(SchemaInitializer.class);
    private static final int SCHEMA_LOCK_CLASS_ID = 0x53534C50; // "SSLP"
    private static final int SCHEMA_LOCK_OBJECT_ID = 0x5343484D; // "SCHM"

    private final CoordinatorProperties props;
    private final Environment env;
    private final DataSource dataSource;

    public SchemaInitializer(CoordinatorProperties props, Environment env, DataSource dataSource) {
        this.props = props;
        this.env = env;
        this.dataSource = dataSource;
    }

    @Override
    public void afterPropertiesSet() {
        applySchema();
    }

    void applySchema() {
        Path schemaPath = Path.of(props.getSyncSchemaFile());
        if (!Files.isReadable(schemaPath)) {
            throw new IllegalStateException("Schema file is not readable: " + schemaPath);
        }

        try (Connection lockConnection = dataSource.getConnection()) {
            if (!tryAcquireSchemaLock(lockConnection)) {
                log.info("event=schema_apply status=skipped reason=lock_not_acquired file={}", schemaPath);
                return;
            }

            log.info("event=schema_apply status=lock_acquired file={}", schemaPath);
            try {
                runSchemaApply(schemaPath);
            } finally {
                releaseSchemaLock(lockConnection);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to coordinate schema apply lock", e);
        }
    }

    private void runSchemaApply(Path schemaPath) {
        List<String> command = new ArrayList<>();
        command.add("psql");
        command.add(psqlDatabaseUrl());
        command.add("-v");
        command.add("ON_ERROR_STOP=1");
        command.add("-q");
        command.add("-f");
        command.add(schemaPath.toString());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        addIfPresent(processBuilder.environment(), "PGUSER", env.getProperty("POSTGRES_USER"));
        addIfPresent(processBuilder.environment(), "PGPASSWORD", env.getProperty("POSTGRES_PASSWORD"));

        log.info("event=schema_apply status=start file={}", schemaPath);
        try {
            Process process = processBuilder.start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IllegalStateException("Schema apply failed with exit code "
                        + exitCode + ": " + output.trim());
            }
            log.info("event=schema_apply status=ok file={}", schemaPath);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to start schema apply command", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while applying schema", e);
        }
    }

    String psqlDatabaseUrl() {
        String rawUrl = firstNonBlank(
                env.getProperty("JDBC_DATABASE_URL"),
                env.getProperty("DATABASE_URL"),
                env.getProperty("spring.datasource.url"),
                "postgres://sync:sync@localhost:5432/sync"
        );

        if (rawUrl.startsWith("jdbc:postgresql://")) {
            return rawUrl.substring("jdbc:".length());
        }
        return rawUrl;
    }

    private boolean tryAcquireSchemaLock(Connection connection) throws SQLException {
        try (PreparedStatement statement =
                     connection.prepareStatement("SELECT pg_try_advisory_lock(?, ?)")) {
            statement.setInt(1, SCHEMA_LOCK_CLASS_ID);
            statement.setInt(2, SCHEMA_LOCK_OBJECT_ID);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next() && rs.getBoolean(1);
            }
        }
    }

    private void releaseSchemaLock(Connection connection) {
        try (PreparedStatement statement =
                     connection.prepareStatement("SELECT pg_advisory_unlock(?, ?)")) {
            statement.setInt(1, SCHEMA_LOCK_CLASS_ID);
            statement.setInt(2, SCHEMA_LOCK_OBJECT_ID);
            try (ResultSet rs = statement.executeQuery()) {
                if (rs.next() && !rs.getBoolean(1)) {
                    log.warn("event=schema_apply status=unlock_skipped reason=lock_not_held");
                }
            }
        } catch (SQLException e) {
            log.warn("event=schema_apply status=unlock_failed error=\"{}\"", e.getMessage());
        }
    }

    private static void addIfPresent(java.util.Map<String, String> environment, String key, String value) {
        if (value != null && !value.isBlank()) {
            environment.put(key, value);
        }
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }
}
