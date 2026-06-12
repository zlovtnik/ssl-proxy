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
import java.sql.SQLException;
import java.util.List;

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
        try (Connection connection = getConnection()) {
            if (!connection.isValid(5)) {
                throw new SQLException("Oracle connection validation returned false");
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

        Path tnsAdmin = validateWallet();
        String password = readPassword(Path.of(props.requiredPassFile()));
        System.setProperty("oracle.net.tns_admin", tnsAdmin.toString());

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
        config.addDataSourceProperty("oracle.net.tns_admin", tnsAdmin.toString());
        return new HikariDataSource(config);
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

    private String readPassword(Path passFile) {
        try {
            if (!Files.isRegularFile(passFile)) {
                throw new IllegalStateException("missing Oracle password file: " + passFile);
            }
            return Files.readString(passFile).stripTrailing();
        } catch (IOException e) {
            throw new IllegalStateException("read Oracle password file " + passFile + ": " + e.getMessage(), e);
        }
    }

    @PreDestroy
    public void close() {
        HikariDataSource existing = dataSource;
        if (existing != null) {
            existing.close();
        }
    }
}
