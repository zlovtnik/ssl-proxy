package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CoordinatorMetricsServiceTest {

    @Test
    void exposesRouteStateAndBackpressureGauges() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        CoordinatorProperties props = new CoordinatorProperties();
        props.setHeartbeatLogIntervalMs(15_000);

        CoordinatorMetricsService service = new CoordinatorMetricsService(registry, props);
        service.recordBackpressureActive(true);
        service.recordRouteState("scan", "scan-request-consumer", true, false);
        service.recordRouteState("result", "oracle-result-consumer", false, true);

        assertEquals(1.0, registry.find("coordinator.backpressure.active").gauge().value());
        assertEquals(1.0, registry.find("coordinator.route.running")
                .tags("role", "scan", "route", "scan-request-consumer")
                .gauge()
                .value());
        assertEquals(1.0, registry.find("coordinator.route.suspended")
                .tags("role", "result", "route", "oracle-result-consumer")
                .gauge()
                .value());
        assertNotNull(registry.find("coordinator.heartbeat.total").counter());
    }
}
