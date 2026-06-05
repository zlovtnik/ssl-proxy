package com.sslproxy.coordinator.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Map;

public class OtlpTracingEndpointEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String ENDPOINT_PROPERTY = "management.otlp.tracing.endpoint";
    static final String EXPORT_ENABLED_PROPERTY = "management.otlp.tracing.export.enabled";

    private static final String PROPERTY_SOURCE_NAME = "coordinatorOtlpTracingEndpointAvailability";

    private final HostResolver hostResolver;

    public OtlpTracingEndpointEnvironmentPostProcessor() {
        this(InetAddress::getAllByName);
    }

    OtlpTracingEndpointEnvironmentPostProcessor(HostResolver hostResolver) {
        this.hostResolver = hostResolver;
    }

    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (environment.containsProperty(EXPORT_ENABLED_PROPERTY)) {
            return;
        }

        String endpoint = environment.getProperty(ENDPOINT_PROPERTY);
        if (!StringUtils.hasText(endpoint)) {
            return;
        }

        String host = endpointHost(endpoint);
        if (!StringUtils.hasText(host) || !isResolvable(host)) {
            disableOtlpExport(environment);
        }
    }

    static String endpointHost(String endpoint) {
        try {
            return new URI(endpoint.trim()).getHost();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private boolean isResolvable(String host) {
        try {
            return hostResolver.resolve(host).length > 0;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static void disableOtlpExport(ConfigurableEnvironment environment) {
        MapPropertySource propertySource = new MapPropertySource(
                PROPERTY_SOURCE_NAME,
                Map.of(EXPORT_ENABLED_PROPERTY, "false")
        );
        environment.getPropertySources().addFirst(propertySource);
    }

    @FunctionalInterface
    interface HostResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }
}
