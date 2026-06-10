package com.sslproxy.coordinator.route;

import com.sslproxy.coordinator.service.PayloadArchiveService;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class RetentionMaintenanceRoute extends RouteBuilder {

    private final PayloadArchiveService payloadArchiveService;

    public RetentionMaintenanceRoute(PayloadArchiveService payloadArchiveService) {
        this.payloadArchiveService = payloadArchiveService;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .log(LoggingLevel.WARN, "event=retention_maintenance status=error error=${exception.message}")
                .continued(true);

        from("timer:wireless-payload-archive?period={{coordinator.wireless-raw-archive-interval-ms}}&daemon=true")
                .routeId("wireless-payload-archive")
                .bean(payloadArchiveService, "archiveDuePayloads");

        from("timer:retention-prune?period={{coordinator.retention-maintenance-interval-ms}}&daemon=true")
                .routeId("retention-prune")
                .bean(payloadArchiveService, "runRetentionPrune");
    }
}
