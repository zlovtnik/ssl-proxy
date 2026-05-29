package com.sslproxy.coordinator.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Component
public class SchemaInitializer implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(SchemaInitializer.class);

    private final CoordinatorProperties props;
    private final Environment env;

    public SchemaInitializer(CoordinatorProperties props, Environment env) {
        this.props = props;
        this.env = env;
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
                env.getProperty("DATABASE_URL"),
                env.getProperty("JDBC_DATABASE_URL"),
                env.getProperty("spring.datasource.url"),
                "postgres://sync:sync@localhost:5432/sync"
        );

        if (rawUrl.startsWith("jdbc:postgresql://")) {
            return rawUrl.substring("jdbc:".length());
        }
        return rawUrl;
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
