package com.sslproxy.coordinator.route;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.oracle.OracleErrorClass;
import com.sslproxy.coordinator.oracle.OracleLoad;
import com.sslproxy.coordinator.oracle.OracleLoadHandler;
import com.sslproxy.coordinator.oracle.OracleResult;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Java-owned Oracle sink worker. It keeps the sync.oracle.load/result topic
 * contract while replacing the old Rust Oracle sink service.
 */
@Component
@ConditionalOnProperty(prefix = "oracle-sink", name = "enabled", havingValue = "true", matchIfMissing = true)
public class OracleLoadRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(OracleLoadRoute.class);

    private final ObjectMapper objectMapper;
    private final OracleLoadHandler loadHandler;

    public OracleLoadRoute(ObjectMapper objectMapper, OracleLoadHandler loadHandler) {
        this.objectMapper = objectMapper;
        this.loadHandler = loadHandler;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .maximumRedeliveries("{{oracle-sink.load-max-retries:3}}")
                .redeliveryDelay(500)
                .useOriginalMessage()
                .to("kafka:{{coordinator.load-topic}}.dlq")
                .handled(true)
                .log(LoggingLevel.ERROR, "event=oracle_load_route status=error error=${exception.message}");

        from("kafka:{{coordinator.load-topic}}"
                + "?groupId={{coordinator.load-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords=1"
                + "&breakOnFirstError=true")
                .routeId("oracle-load-consumer")
                .process(exchange -> {
                    String body = exchange.getIn().getBody(String.class);
                    OracleResult result = handleLoadMessage(body);
                    exchange.getIn().setBody(objectMapper.writeValueAsString(result));
                })
                .to("kafka:{{coordinator.result-topic}}");
    }

    OracleResult handleLoadMessage(String body) {
        String jobId = "";
        String batchId = "";
        try {
            OracleLoad load = objectMapper.readValue(body, OracleLoad.class);
            jobId = load.jobId();
            batchId = load.batchId();
            OracleResult result = loadHandler.handle(load);
            log.info("event=oracle_load_route status=handled batch_id={} result={}",
                    load.batchId(), result.status());
            return result;
        } catch (Exception e) {
            String failureStage = batchId.isBlank() ? "decode" : "handle";
            OracleErrorClass errorClass = batchId.isBlank() || e instanceof com.fasterxml.jackson.core.JsonProcessingException
                    ? OracleErrorClass.PERMANENT
                    : OracleErrorClass.classify(e.getMessage());
            log.error("event=oracle_load_route status={}_failed job_id={} batch_id={} error=\"{}\"",
                    failureStage, jobId, batchId, sanitize(e.getMessage()));
            return OracleResult.failure(jobId, batchId, errorClass,
                    failureStage + " sync.oracle.load message: " + e.getMessage(),
                    java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC)
                            .format(java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        }
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
