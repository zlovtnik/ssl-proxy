package com.sslproxy.coordinator.route;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.processor.PayloadAuditRecordProcessor;
import org.apache.camel.Exchange;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Consumes direct proxy payload-audit records and translates them into the
 * coordinator-owned sync ledger for Oracle dispatch.
 */
@Component
public class PayloadAuditRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(PayloadAuditRoute.class);

    private final CoordinatorProperties props;
    private final PayloadAuditRecordProcessor payloadAuditRecordProcessor;

    public PayloadAuditRoute(CoordinatorProperties props,
                             PayloadAuditRecordProcessor payloadAuditRecordProcessor) {
        this.props = props;
        this.payloadAuditRecordProcessor = payloadAuditRecordProcessor;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .maximumRedeliveries("{{coordinator.payload-audit-route-max-retries:3}}")
                .redeliveryDelay(500)
                .useOriginalMessage()
                .handled(true)
                .process(exchange -> logRouteFailure(exchange, props.payloadAuditTopic() + ".dlq"))
                .to("kafka:{{coordinator.payload-audit-topic}}.dlq");

        from("kafka:{{coordinator.payload-audit-topic}}"
                + "?groupId={{coordinator.payload-audit-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.scan-fetch-count}}"
                + "&breakOnFirstError=true")
                .routeId("payload-audit-consumer")
                .process(exchange -> {
                    String body = exchange.getIn().getBody(String.class);
                    int payloadBytes = body == null ? 0 : body.getBytes(StandardCharsets.UTF_8).length;
                    log.atTrace()
                            .addKeyValue("event", "payload_audit_ingest")
                            .addKeyValue("status", "received")
                            .addKeyValue("route", "payload-audit-consumer")
                            .addKeyValue("topic", props.payloadAuditTopic())
                            .addKeyValue("consumer_group", props.payloadAuditConsumer())
                            .addKeyValue("payload_bytes", payloadBytes)
                            .log("payload audit received");
                })
                .process(payloadAuditRecordProcessor);

        from("timer:payload-audit-flush?period=1000&daemon=true")
                .routeId("payload-audit-flush-timer")
                .bean(payloadAuditRecordProcessor, "flushPending")
                .log(LoggingLevel.TRACE, "event=payload_audit_flush_timer status=tick");
    }

    private void logRouteFailure(Exchange exchange, String dlqTopic) {
        Exception error = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
        log.atError()
                .addKeyValue("event", "payload_audit_ingest")
                .addKeyValue("status", "dlq")
                .addKeyValue("dlq_topic", dlqTopic)
                .addKeyValue("error", sanitize(error == null ? "" : error.getMessage()))
                .log("payload audit routed to DLQ");
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
