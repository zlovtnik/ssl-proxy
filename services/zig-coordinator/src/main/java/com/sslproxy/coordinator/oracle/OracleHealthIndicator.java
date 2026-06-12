package com.sslproxy.coordinator.oracle;

import com.sslproxy.coordinator.config.OracleSinkProperties;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "oracle-sink", name = "enabled", havingValue = "true")
public class OracleHealthIndicator implements HealthIndicator {

    private final OracleConnectionFactory connectionFactory;
    private final OracleSinkProperties props;

    public OracleHealthIndicator(OracleConnectionFactory connectionFactory, OracleSinkProperties props) {
        this.connectionFactory = connectionFactory;
        this.props = props;
    }

    @Override
    public Health health() {
        try {
            connectionFactory.checkConnectivity();
            return Health.up()
                    .withDetail("user", props.requiredUser())
                    .withDetail("conn", props.tnsAliasForValidation().orElse("jdbc-descriptor"))
                    .build();
        } catch (Exception e) {
            return Health.down()
                    .withDetail("error", sanitize(e.getMessage()))
                    .build();
        }
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
