package com.sslproxy.coordinator.config;

import com.sslproxy.coordinator.service.CursorService;
import com.sslproxy.coordinator.service.HealthCheckService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Startup lifecycle handler that mirrors the Zig main.zig initialization:
 * 1. Logs configuration
 * 2. Runs healthcheck
 * 3. Ensures cursors exist for all configured streams
 */
@Component
public class CoordinatorStartupListener {

    private static final Logger log = LoggerFactory.getLogger(CoordinatorStartupListener.class);

    private final CoordinatorProperties props;
    private final HealthCheckService healthCheckService;
    private final CursorService cursorService;

    public CoordinatorStartupListener(CoordinatorProperties props,
                                      HealthCheckService healthCheckService,
                                      CursorService cursorService) {
        this.props = props;
        this.healthCheckService = healthCheckService;
        this.cursorService = cursorService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        log.info("event=process_start mode={} stream_name={} scan_topic={} load_topic={} result_topic={}",
                props.mode(), props.streamName(),
                props.scanTopic(), props.loadTopic(), props.resultTopic());

        // Run healthcheck (same as Zig coordinator healthcheck mode)
        healthCheckService.checkHealth();

        // Ensure cursors for all streams (same as main.zig ensureCursors())
        String cursor = cursorService.ensureCursors();
        log.info("event=ready mode={} primary_stream={} cursor={}",
                props.mode(), props.streamName(), cursor);
    }
}