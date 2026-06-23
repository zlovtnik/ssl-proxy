package com.sslproxy.coordinator.oracle;

import com.sslproxy.coordinator.config.OracleSinkProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

class OracleHealthIndicatorTest {

    @Test
    void reportsUpWhenConnectivityCheckSucceeds() {
        OracleConnectionFactory connectionFactory = mock(OracleConnectionFactory.class);
        OracleHealthIndicator indicator = new OracleHealthIndicator(connectionFactory, props());

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals("USCIS_APP", health.getDetails().get("user"));
        assertEquals("mainerc_high", health.getDetails().get("conn"));
    }

    @Test
    void reportsDownWithSanitizedErrorWhenConnectivityCheckFails() throws Exception {
        OracleConnectionFactory connectionFactory = mock(OracleConnectionFactory.class);
        doThrow(new SQLException("ORA-03114\nnot connected")).when(connectionFactory).checkConnectivity();
        OracleHealthIndicator indicator = new OracleHealthIndicator(connectionFactory, props());

        Health health = indicator.health();

        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("ORA-03114 not connected", health.getDetails().get("error"));
    }

    private OracleSinkProperties props() {
        return new OracleSinkProperties(
                true,
                true,
                false,
                "mainerc_high",
                "",
                "USCIS_APP",
                "/run/secrets/oracle_password.txt",
                "/app/wallet",
                1,
                0,
                1_000,
                1_000,
                1_000,
                1_000,
                30_000,
                "SELECT 1 FROM DUAL",
                5,
                3
        );
    }
}
