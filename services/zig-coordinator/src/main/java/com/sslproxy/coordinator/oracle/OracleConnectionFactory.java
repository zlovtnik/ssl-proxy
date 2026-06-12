package com.sslproxy.coordinator.oracle;

import com.sslproxy.coordinator.config.OracleSinkProperties;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class OracleConnectionFactory {

    private final OracleSinkProperties props;
    private volatile HikariDataSource dataSource;

    public OracleConnectionFactory(OracleSinkProperties props) {
        this.props = props;
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
        config.setPoolName("oracle-sink");
        config.setDriverClassName("oracle.jdbc.OracleDriver");
        config.setJdbcUrl(props.effectiveJdbcUrl());
        config.setUsername(props.requiredUser());
        config.setPassword(password);
        config.setMaximumPoolSize(props.maximumPoolSize());
        config.setMinimumIdle(props.minimumIdle());
        config.setConnectionTimeout(props.connectionTimeoutMs());
        config.setIdleTimeout(props.idleTimeoutMs());
        config.setMaxLifetime(props.maxLifetimeMs());
        config.setAutoCommit(false);
        config.setConnectionTestQuery("SELECT 1 FROM DUAL");
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
            throw new IllegalStateException("wallet directory missing: " + tnsAdmin);
        }
        for (String file : List.of("tnsnames.ora", "sqlnet.ora", "cwallet.sso")) {
            Path candidate = tnsAdmin.resolve(file);
            if (!Files.isRegularFile(candidate)) {
                throw new IllegalStateException("missing Oracle wallet artifact: " + candidate);
            }
        }
        return tnsAdmin;
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

    @PreDestroy
    public void close() {
        HikariDataSource existing = dataSource;
        if (existing != null) {
            existing.close();
        }
    }

    record OracleConfiguration(Path tnsAdmin, String password) {
    }
}
