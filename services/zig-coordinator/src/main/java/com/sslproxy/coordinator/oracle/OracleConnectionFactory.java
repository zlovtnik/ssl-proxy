package com.sslproxy.coordinator.oracle;

import com.sslproxy.coordinator.config.OracleSinkProperties;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class OracleConnectionFactory {

    private static final Logger log = LoggerFactory.getLogger(OracleConnectionFactory.class);
    private static final String CONNECTION_TEST_QUERY = "SELECT 1 FROM DUAL";

    private final OracleSinkProperties props;
    private final MeterRegistry meterRegistry;
    private volatile HikariDataSource dataSource;

    public OracleConnectionFactory(OracleSinkProperties props, MeterRegistry meterRegistry) {
        this.props = props;
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void validateStartupConfiguration() {
        if (props.enabled()) {
            validateConfiguration();
        }
    }

    public Connection getConnection() throws SQLException {
        return dataSource().getConnection();
    }

    public void checkConnectivity() throws SQLException {
        if (!props.enabled()) {
            return;
        }
        try (Connection connection = getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT 1 FROM DUAL")) {
            statement.setQueryTimeout(props.statementTimeoutSecs());
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    throw new SQLException("Oracle validation query returned no rows");
                }
            }
        }
    }

    private HikariDataSource dataSource() {
        HikariDataSource existing = dataSource;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (dataSource == null) {
                dataSource = createDataSource();
            }
            return dataSource;
        }
    }

    private HikariDataSource createDataSource() {
        if (!props.enabled()) {
            throw new IllegalStateException("Oracle sink is disabled");
        }

        OracleConfiguration preflight = validateConfiguration();
        Path tnsAdmin = preflight.tnsAdmin();
        String password = preflight.password();
        String walletLocation = walletLocation(tnsAdmin);
        System.setProperty("oracle.net.tns_admin", tnsAdmin.toString());
        System.setProperty("oracle.net.wallet_location", walletLocation);
        System.setProperty("oracle.net.ssl_server_dn_match", "true");

        HikariConfig config = new HikariConfig();
        config.setPoolName("coordinator-oracle");
        config.setDriverClassName("oracle.jdbc.OracleDriver");
        config.setJdbcUrl(props.effectiveJdbcUrl());
        config.setUsername(props.requiredUser());
        config.setPassword(password);
        config.setMaximumPoolSize(props.maximumPoolSize());
        config.setMinimumIdle(props.minimumIdle());
        config.setConnectionTimeout(props.connectionTimeoutMs());
        config.setValidationTimeout(props.validationTimeoutMs());
        config.setIdleTimeout(props.idleTimeoutMs());
        config.setMaxLifetime(props.maxLifetimeMs());
        config.setLeakDetectionThreshold(props.leakDetectionThresholdMs());
        config.setAutoCommit(false);
        config.setConnectionTestQuery(CONNECTION_TEST_QUERY);
        config.setKeepaliveTime(60_000);
        config.setConnectionInitSql(props.effectiveConnectionInitSql());
        config.setMetricRegistry(meterRegistry);
        config.addDataSourceProperty("oracle.net.tns_admin", tnsAdmin.toString());
        config.addDataSourceProperty("oracle.net.wallet_location", walletLocation);
        config.addDataSourceProperty("oracle.net.ssl_server_dn_match", "true");
        return new HikariDataSource(config);
    }

    OracleConfiguration validateConfiguration() {
        Path tnsAdmin = validateWallet();
        props.tnsAliasForValidation().ifPresent(alias -> validateTnsAlias(tnsAdmin, alias));
        String password = readPassword(Path.of(props.requiredPassFile()));
        return new OracleConfiguration(tnsAdmin, password);
    }

    private Path validateWallet() {
        Path tnsAdmin = Path.of(props.requiredTnsAdmin());
        if (!Files.isDirectory(tnsAdmin)) {
            throw new IllegalStateException("wallet directory missing: " + tnsAdmin + "; " + walletDiagnostics(tnsAdmin));
        }
        for (String file : List.of("tnsnames.ora", "sqlnet.ora", "cwallet.sso")) {
            Path candidate = tnsAdmin.resolve(file);
            if (!Files.isRegularFile(candidate)) {
                throw new IllegalStateException("missing Oracle wallet artifact: " + candidate + "; " + walletDiagnostics(tnsAdmin));
            }
        }
        return tnsAdmin;
    }

    private String walletDiagnostics(Path tnsAdmin) {
        StringBuilder diagnostics = new StringBuilder("wallet diagnostics: path=")
                .append(tnsAdmin)
                .append(" exists=")
                .append(Files.exists(tnsAdmin))
                .append(" directory=")
                .append(Files.isDirectory(tnsAdmin))
                .append(" readable=")
                .append(Files.isReadable(tnsAdmin));

        if (!Files.isDirectory(tnsAdmin)) {
            return diagnostics.toString();
        }

        try (Stream<Path> entries = Files.list(tnsAdmin)) {
            String listedEntries = entries
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .limit(20)
                    .map(this::walletEntryDiagnostic)
                    .collect(Collectors.joining(", "));
            diagnostics.append(" entries=[")
                    .append(listedEntries)
                    .append("]");
        } catch (IOException | SecurityException e) {
            diagnostics.append(" entries_error=\"")
                    .append(sanitize(e.getMessage()))
                    .append("\"");
        }
        return diagnostics.toString();
    }

    private String walletEntryDiagnostic(Path entry) {
        return entry.getFileName()
                + "{regular="
                + Files.isRegularFile(entry)
                + ",directory="
                + Files.isDirectory(entry)
                + ",readable="
                + Files.isReadable(entry)
                + "}";
    }

    private void validateTnsAlias(Path tnsAdmin, String alias) {
        Path tnsNames = tnsAdmin.resolve("tnsnames.ora");
        try {
            String contents = Files.readString(tnsNames);
            Pattern aliasPattern = Pattern.compile("(?im)^\\s*" + Pattern.quote(alias) + "\\s*=");
            if (!aliasPattern.matcher(contents).find()) {
                throw new IllegalStateException("Oracle TNS alias not found in " + tnsNames + ": " + alias);
            }
        } catch (IOException e) {
            throw new IllegalStateException("read Oracle tnsnames.ora " + tnsNames + ": " + e.getMessage(), e);
        }
    }

    private String readPassword(Path passFile) {
        try {
            if (!Files.isRegularFile(passFile)) {
                throw new IllegalStateException("missing Oracle password file: " + passFile);
            }
            String password = Files.readString(passFile).stripTrailing();
            if (password.isBlank()) {
                throw new IllegalStateException("Oracle password file is empty: " + passFile);
            }
            return password;
        } catch (IOException e) {
            throw new IllegalStateException("read Oracle password file " + passFile + ": " + e.getMessage(), e);
        }
    }

    private String walletLocation(Path tnsAdmin) {
        return "(SOURCE=(METHOD=FILE)(METHOD_DATA=(DIRECTORY=" + tnsAdmin + ")))";
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }

    @PreDestroy
    public void close() {
        HikariDataSource existing = dataSource;
        if (existing != null && !existing.isClosed()) {
            log.info("event=oracle_pool status=closing pool={}", existing.getPoolName());
            existing.close();
            log.info("event=oracle_pool status=closed");
        }
    }

    record OracleConfiguration(Path tnsAdmin, String password) {
    }
}
