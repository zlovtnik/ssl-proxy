package com.sslproxy.coordinator.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

@Configuration(proxyBeanMethods = false)
public class DataSourceConfig {

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @ConfigurationProperties("spring.datasource.hikari")
    public HikariDataSource dataSource(Environment env) {
        DatabaseUrl databaseUrl = normalizeDatabaseUrl(firstNonBlank(
                env.getProperty("JDBC_DATABASE_URL"),
                env.getProperty("DATABASE_URL"),
                env.getProperty("spring.datasource.url"),
                "jdbc:postgresql://localhost:5432/sync"
        ));

        HikariDataSource dataSource = new HikariDataSource();
        dataSource.setJdbcUrl(databaseUrl.jdbcUrl());
        dataSource.setUsername(firstNonBlank(
                databaseUrl.username(),
                env.getProperty("POSTGRES_USER"),
                env.getProperty("spring.datasource.username"),
                "sync"
        ));
        dataSource.setPassword(firstNonBlank(
                databaseUrl.password(),
                env.getProperty("POSTGRES_PASSWORD"),
                env.getProperty("spring.datasource.password"),
                ""
        ));
        dataSource.setDriverClassName(env.getProperty(
                "spring.datasource.driver-class-name",
                "org.postgresql.Driver"
        ));
        return dataSource;
    }

    static DatabaseUrl normalizeDatabaseUrl(String rawUrl) {
        if (rawUrl.startsWith("jdbc:postgresql://")) {
            return new DatabaseUrl(rawUrl, null, null);
        }

        if (rawUrl.startsWith("postgres://") || rawUrl.startsWith("postgresql://")) {
            URI uri = URI.create(rawUrl);
            StringBuilder jdbcUrl = new StringBuilder("jdbc:postgresql://");
            jdbcUrl.append(uri.getHost());
            if (uri.getPort() > -1) {
                jdbcUrl.append(':').append(uri.getPort());
            }
            jdbcUrl.append(uri.getRawPath() == null || uri.getRawPath().isEmpty()
                    ? "/sync"
                    : uri.getRawPath());
            if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) {
                jdbcUrl.append('?').append(uri.getRawQuery());
            }

            String username = null;
            String password = null;
            String userInfo = uri.getRawUserInfo();
            if (userInfo != null && !userInfo.isEmpty()) {
                String[] parts = userInfo.split(":", 2);
                username = decode(parts[0]);
                if (parts.length > 1) {
                    password = decode(parts[1]);
                }
            }

            return new DatabaseUrl(jdbcUrl.toString(), username, password);
        }

        throw new IllegalArgumentException("Unsupported PostgreSQL URL scheme: " + rawUrl);
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static String decode(String value) {
        StringBuilder decoded = new StringBuilder(value.length());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int index = 0; index < value.length(); ) {
            char character = value.charAt(index);
            if (character == '%') {
                if (index + 2 >= value.length()) {
                    throw new IllegalArgumentException("Malformed percent-encoded credential");
                }
                int high = hexDigit(value.charAt(index + 1));
                int low = hexDigit(value.charAt(index + 2));
                if (high < 0 || low < 0) {
                    throw new IllegalArgumentException("Malformed percent-encoded credential");
                }
                bytes.write((high << 4) + low);
                index += 3;
                continue;
            }

            flushDecodedBytes(bytes, decoded);
            decoded.append(character);
            index++;
        }
        flushDecodedBytes(bytes, decoded);
        return decoded.toString();
    }

    private static void flushDecodedBytes(ByteArrayOutputStream bytes, StringBuilder decoded) {
        if (bytes.size() == 0) {
            return;
        }
        decoded.append(bytes.toString(StandardCharsets.UTF_8));
        bytes.reset();
    }

    private static int hexDigit(char character) {
        if (character >= '0' && character <= '9') {
            return character - '0';
        }
        if (character >= 'a' && character <= 'f') {
            return character - 'a' + 10;
        }
        if (character >= 'A' && character <= 'F') {
            return character - 'A' + 10;
        }
        return -1;
    }

    record DatabaseUrl(String jdbcUrl, String username, String password) {
    }
}
