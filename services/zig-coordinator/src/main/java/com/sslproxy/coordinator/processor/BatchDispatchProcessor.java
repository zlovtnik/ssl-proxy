package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.model.DispatchPayload;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Dispatches the next batch to the Oracle worker via sync.oracle.load topic.
 *
 * Mirrors sync_handlers.zig dispatchNextBatch() logic:
 * 1. Call coordinator.get_next_batch() to select a batch
 * 2. If a batch is returned, publish the DispatchPayload JSON to sync.oracle.load
 * 3. On publish failure, call mark_batch_dispatch_failed() or release_batch_dispatch()
 *
 * Called in a loop up to dispatch_batch_size times per main loop iteration.
 */
@Component
public class BatchDispatchProcessor implements Processor {

    private static final Logger log = LoggerFactory.getLogger(BatchDispatchProcessor.class);

    private final DatabaseService databaseService;
    private final CoordinatorProperties props;
    private final ObjectMapper objectMapper;
    private final ProducerTemplate producerTemplate;

    public BatchDispatchProcessor(DatabaseService databaseService,
                                  CoordinatorProperties props,
                                  ObjectMapper objectMapper,
                                  ProducerTemplate producerTemplate) {
        this.databaseService = databaseService;
        this.props = props;
        this.objectMapper = objectMapper;
        this.producerTemplate = producerTemplate;
    }

    @Override
    public void process(Exchange exchange) {
        try {
            Optional<String> batchJsonOpt = databaseService.getNextBatch();
            if (batchJsonOpt.isEmpty() || batchJsonOpt.get().isEmpty()) {
                // No batch to dispatch -- set body to false so caller knows no work was done
                exchange.getIn().setBody(false);
                return;
            }

            String batchJson = batchJsonOpt.get();
            DispatchPayload payload = objectMapper.readValue(batchJson, DispatchPayload.class);
            String dispatchJson = objectMapper.writeValueAsString(payload);

            log.info("event=batch_dispatch status=selected batch_id={} stream_name={} attempt={}",
                    payload.getBatchId(), payload.getStreamName(), payload.getAttempt());

            // Publish to sync.oracle.load topic
            try {
                producerTemplate.sendBody(
                        "kafka:" + props.getLoadTopic()
                                + "?groupId=" + props.getLoadConsumer(),
                        dispatchJson
                );

                log.info("event=batch_dispatch status=published batch_id={} topic={}",
                        payload.getBatchId(), props.getLoadTopic());

                exchange.getIn().setBody(true);
            } catch (Exception e) {
                log.error("event=batch_dispatch status=publish_failed batch_id={} error=\"{}\"",
                        payload.getBatchId(), e.getMessage());

                // Attempt to mark the batch dispatch as failed in DB
                try {
                    databaseService.markBatchDispatchFailed(batchJson, e.getMessage());
                    log.info("event=batch_dispatch status=marked_failed batch_id={}", payload.getBatchId());
                } catch (Exception dbErr) {
                    log.error("event=batch_dispatch status=mark_failed_error batch_id={} error=\"{}\"",
                            payload.getBatchId(), dbErr.getMessage());
                    // Fallback: release the batch dispatch without tracking failure
                    try {
                        databaseService.releaseBatchDispatch(batchJson, e.getMessage());
                    } catch (Exception releaseErr) {
                        log.error("event=batch_dispatch status=release_failed batch_id={} error=\"{}\"",
                                payload.getBatchId(), releaseErr.getMessage());
                    }
                }

                exchange.getIn().setBody(false);
            }
        } catch (JsonProcessingException e) {
            log.error("event=batch_dispatch status=deserialize_failed error=\"{}\"", e.getMessage());
            exchange.getIn().setBody(false);
        } catch (Exception e) {
            log.error("event=batch_dispatch status=failed error=\"{}\"", e.getMessage());
            exchange.getIn().setBody(false);
        }
    }
}
