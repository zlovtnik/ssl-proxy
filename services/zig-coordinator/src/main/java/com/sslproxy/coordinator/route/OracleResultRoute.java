package com.sslproxy.coordinator.route;

import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.processor.ResultProcessor;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Consumes Oracle results from sync.oracle.result topic.
 * Replaces sync_handlers.zig handleResults() and the CLI-based
 * service_redpanda.zig pullResultBatch().
 *
 * Each result message is accumulated into batches by ResultProcessor
 * and flushed to the DB via coordinator.process_batch_results().
 */
@Component
public class OracleResultRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(OracleResultRoute.class);

    private final CoordinatorProperties props;
    private final ResultProcessor resultProcessor;

    public OracleResultRoute(CoordinatorProperties props,
                             ResultProcessor resultProcessor) {
        this.props = props;
        this.resultProcessor = resultProcessor;
    }

    @Override
    public void configure() {
        onException(Exception.class)
                .log(LoggingLevel.ERROR, "event=batch_result_ingest status=error error=${exception.message}")
                .continued(true);

        // Consume from sync.oracle.result with the zig-coordinator-result consumer group
        from("kafka:{{coordinator.result-topic}}"
                + "?groupId={{coordinator.result-consumer}}"
                + "&autoOffsetReset=earliest"
                + "&maxPollRecords={{coordinator.result-fetch-count}}"
                + "&consumersCount=1"
                + "&breakOnFirstError=true")
        .routeId("oracle-result-consumer")
        .log(LoggingLevel.TRACE, "Received Oracle result: ${body}")
        .process(resultProcessor);

        // Timer-based flush for partial batches — ensures results don't sit in the
        // accumulator indefinitely when Kafka delivers fewer messages than the batch size
        from("timer:result-flush?period=1000&daemon=true")
                .routeId("oracle-result-flush-timer")
                .bean(resultProcessor, "flushPending")
                .log(LoggingLevel.TRACE, "event=result_flush_timer status=tick");
    }
}
