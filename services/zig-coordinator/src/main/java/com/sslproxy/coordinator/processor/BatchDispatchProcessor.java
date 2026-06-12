package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import com.sslproxy.coordinator.fp.DbResult;
import com.sslproxy.coordinator.oracle.OracleLoad;
import com.sslproxy.coordinator.service.DatabaseService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.ProducerTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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
        switch (databaseService.getNextBatch()) {
            case DbResult.Empty<String> ignored -> exchange.getIn().setBody(false);
            case DbResult.Err<String> err -> {
                log.error("event=batch_dispatch status=db_error operation={} error=\"{}\"",
                        err.operation(), sanitize(err.cause().getMessage()));
                exchange.getIn().setBody(false);
            }
            case DbResult.Ok<String> ok -> dispatchBatch(ok.value(), exchange);
        }
    }

    private void dispatchBatch(String batchJson, Exchange exchange) {
        try {
            OracleLoad payload = objectMapper.readValue(batchJson, OracleLoad.class);
            validateLoad(payload);
            String dispatchJson = objectMapper.writeValueAsString(payload);

            log.info("event=batch_dispatch status=selected batch_id={} stream_name={} attempt={}",
                    payload.batchId(), payload.streamName(), payload.attempt());

            try {
                producerTemplate.sendBody(
                        "kafka:" + props.loadTopic()
                                + "?groupId=" + props.loadConsumer(),
                        dispatchJson
                );

                log.info("event=batch_dispatch status=published batch_id={} topic={}",
                        payload.batchId(), props.loadTopic());

                exchange.getIn().setBody(true);
            } catch (Exception e) {
                log.error("event=batch_dispatch status=publish_failed batch_id={} error=\"{}\"",
                        payload.batchId(), sanitize(e.getMessage()));
                handlePublishFailure(batchJson, payload, e);
                exchange.getIn().setBody(false);
            }
        } catch (JsonProcessingException e) {
            log.error("event=batch_dispatch status=deserialize_failed error=\"{}\"", sanitize(e.getMessage()));
            handleDispatchFailure(batchJson, e);
            exchange.getIn().setBody(false);
        } catch (IllegalArgumentException e) {
            log.error("event=batch_dispatch status=validation_failed error=\"{}\"", sanitize(e.getMessage()));
            handleDispatchFailure(batchJson, e);
            exchange.getIn().setBody(false);
        } catch (Exception e) {
            log.error("event=batch_dispatch status=failed error=\"{}\"", sanitize(e.getMessage()));
            handleDispatchFailure(batchJson, e);
            exchange.getIn().setBody(false);
        }
    }

    private void validateLoad(OracleLoad load) {
        if (load == null) {
            throw new IllegalArgumentException("sync.oracle.load payload must not be null");
        }
        if (load.jobId().isBlank()) {
            throw new IllegalArgumentException("job_id must not be empty");
        }
        if (load.batchId().isBlank()) {
            throw new IllegalArgumentException("batch_id must not be empty");
        }
        if (load.streamName().isBlank()) {
            throw new IllegalArgumentException("stream_name must not be empty");
        }
        if (load.payloadRef().isBlank()) {
            throw new IllegalArgumentException("payload_ref must not be empty");
        }
    }

    private void handleDispatchFailure(String batchJson, Exception dispatchError) {
        switch (databaseService.markBatchDispatchFailed(batchJson, dispatchError.getMessage())) {
            case DbResult.Ok<String> ignored ->
                    log.info("event=batch_dispatch status=marked_failed");
            case DbResult.Empty<String> ignored ->
                    log.info("event=batch_dispatch status=marked_failed");
            case DbResult.Err<String> err -> {
                log.error("event=batch_dispatch status=mark_failed_error operation={} error=\"{}\"",
                        err.operation(), sanitize(err.cause().getMessage()));
                releaseBatch(batchJson, dispatchError);
            }
        }
    }

    private void handlePublishFailure(String batchJson, OracleLoad payload, Exception publishError) {
        switch (databaseService.markBatchDispatchFailed(batchJson, publishError.getMessage())) {
            case DbResult.Ok<String> ignored ->
                    log.info("event=batch_dispatch status=marked_failed batch_id={}", payload.batchId());
            case DbResult.Empty<String> ignored ->
                    log.info("event=batch_dispatch status=marked_failed batch_id={}", payload.batchId());
            case DbResult.Err<String> err -> {
                log.error("event=batch_dispatch status=mark_failed_error batch_id={} operation={} error=\"{}\"",
                        payload.batchId(), err.operation(), sanitize(err.cause().getMessage()));
                releaseBatch(batchJson, payload, publishError);
            }
        }
    }

    private void releaseBatch(String batchJson, Exception dispatchError) {
        switch (databaseService.releaseBatchDispatch(batchJson, dispatchError.getMessage())) {
            case DbResult.Ok<String> ignored ->
                    log.info("event=batch_dispatch status=released");
            case DbResult.Empty<String> ignored ->
                    log.info("event=batch_dispatch status=released");
            case DbResult.Err<String> err ->
                    log.error("event=batch_dispatch status=release_failed operation={} error=\"{}\"",
                            err.operation(), sanitize(err.cause().getMessage()));
        }
    }

    private void releaseBatch(String batchJson, OracleLoad payload, Exception publishError) {
        switch (databaseService.releaseBatchDispatch(batchJson, publishError.getMessage())) {
            case DbResult.Ok<String> ignored ->
                    log.info("event=batch_dispatch status=released batch_id={}", payload.batchId());
            case DbResult.Empty<String> ignored ->
                    log.info("event=batch_dispatch status=released batch_id={}", payload.batchId());
            case DbResult.Err<String> err ->
                    log.error("event=batch_dispatch status=release_failed batch_id={} operation={} error=\"{}\"",
                            payload.batchId(), err.operation(), sanitize(err.cause().getMessage()));
        }
    }

    private String sanitize(String message) {
        if (message == null || message.isBlank()) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
