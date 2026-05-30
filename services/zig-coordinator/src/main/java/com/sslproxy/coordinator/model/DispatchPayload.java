package com.sslproxy.coordinator.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a batch dispatch payload sent to sync.oracle.load topic.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DispatchPayload {

    @JsonProperty("job_id")
    private String jobId = "";

    @JsonProperty("batch_id")
    private String batchId;

    @JsonProperty("stream_name")
    private String streamName = "";

    @JsonProperty("attempt")
    private long attempt = 0;

    public String getJobId() { return jobId; }
    public void setJobId(String jobId) { this.jobId = jobId; }

    public String getBatchId() { return batchId; }
    public void setBatchId(String batchId) { this.batchId = batchId; }

    public String getStreamName() { return streamName; }
    public void setStreamName(String streamName) { this.streamName = streamName; }

    public long getAttempt() { return attempt; }
    public void setAttempt(long attempt) { this.attempt = attempt; }
}
