package com.sslproxy.coordinator.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class OtlpTracingEndpointEnvironmentPostProcessorTest {

    @Test
    void disablesOtlpExportWhenEndpointHostCannotResolve() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(OtlpTracingEndpointEnvironmentPostProcessor.ENDPOINT_PROPERTY, "http://otel-collector:4317");

        postProcessor((host) -> {
            throw new UnknownHostException(host);
        }).postProcessEnvironment(environment, null);

        assertEquals("false", environment.getProperty(OtlpTracingEndpointEnvironmentPostProcessor.EXPORT_ENABLED_PROPERTY));
    }

    @Test
    void leavesOtlpExportUnsetWhenEndpointHostResolves() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(OtlpTracingEndpointEnvironmentPostProcessor.ENDPOINT_PROPERTY, "http://localhost:4317");

        postProcessor((host) -> new InetAddress[] {InetAddress.getLoopbackAddress()})
                .postProcessEnvironment(environment, null);

        assertNull(environment.getProperty(OtlpTracingEndpointEnvironmentPostProcessor.EXPORT_ENABLED_PROPERTY));
    }

    @Test
    void doesNotOverrideExplicitOtlpExportSetting() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(OtlpTracingEndpointEnvironmentPostProcessor.ENDPOINT_PROPERTY, "http://otel-collector:4317")
                .withProperty(OtlpTracingEndpointEnvironmentPostProcessor.EXPORT_ENABLED_PROPERTY, "true");

        postProcessor((host) -> {
            throw new UnknownHostException(host);
        }).postProcessEnvironment(environment, null);

        assertEquals("true", environment.getProperty(OtlpTracingEndpointEnvironmentPostProcessor.EXPORT_ENABLED_PROPERTY));
    }

    @Test
    void leavesOtlpExportUnsetWhenEndpointIsBlank() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(OtlpTracingEndpointEnvironmentPostProcessor.ENDPOINT_PROPERTY, " ");

        postProcessor((host) -> {
            throw new UnknownHostException(host);
        }).postProcessEnvironment(environment, null);

        assertNull(environment.getProperty(OtlpTracingEndpointEnvironmentPostProcessor.EXPORT_ENABLED_PROPERTY));
    }

    @Test
    void disablesOtlpExportWhenEndpointHasNoHost() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty(OtlpTracingEndpointEnvironmentPostProcessor.ENDPOINT_PROPERTY, "otel-collector:4317");

        postProcessor((host) -> new InetAddress[] {InetAddress.getLoopbackAddress()})
                .postProcessEnvironment(environment, null);

        assertEquals("false", environment.getProperty(OtlpTracingEndpointEnvironmentPostProcessor.EXPORT_ENABLED_PROPERTY));
    }

    private static OtlpTracingEndpointEnvironmentPostProcessor postProcessor(
            OtlpTracingEndpointEnvironmentPostProcessor.HostResolver hostResolver
    ) {
        return new OtlpTracingEndpointEnvironmentPostProcessor(hostResolver);
    }
}
