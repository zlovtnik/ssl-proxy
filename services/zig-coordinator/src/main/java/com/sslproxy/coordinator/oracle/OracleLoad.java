package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record OracleLoad(
        @JsonProperty("job_id") String jobId,
        @JsonProperty("batch_id") String batchId,
        @JsonProperty("batch_no") Integer batchNo,
        @JsonProperty("stream_name") String streamName,
        @JsonProperty("payload_ref") String payloadRef,
        @JsonProperty("cursor_start") String cursorStart,
        @JsonProperty("cursor_end") String cursorEnd,
        @JsonProperty("attempt") Integer attempt
) {
    public OracleLoad {
        jobId = textOrEmpty(jobId);
        batchId = textOrEmpty(batchId);
        streamName = textOrEmpty(streamName);
        payloadRef = textOrEmpty(payloadRef);
        cursorStart = textOrEmpty(cursorStart);
        cursorEnd = textOrEmpty(cursorEnd);
        attempt = attempt == null ? 0 : attempt;
    }

    private static String textOrEmpty(String value) {
        return value == null ? "" : value;
    }
}
