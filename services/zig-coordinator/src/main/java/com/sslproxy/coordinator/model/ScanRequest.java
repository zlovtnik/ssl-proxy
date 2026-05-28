package com.sslproxy.coordinator.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a scan request message from sync.scan.request topic.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanRequest {

    @JsonProperty("stream_name")
    private String streamName;

    @JsonProperty("dedupe_key")
    private String dedupeKey;

    @JsonProperty("payload_ref")
    private String payloadRef;

    @JsonProperty("observed_at")
    private String observedAt;

    public String getStreamName() { return streamName; }
    public void setStreamName(String streamName) { this.streamName = streamName; }

    public String getDedupeKey() { return dedupeKey; }
    public void setDedupeKey(String dedupeKey) { this.dedupeKey = dedupeKey; }

    public String getPayloadRef() { return payloadRef; }
    public void setPayloadRef(String payloadRef) { this.payloadRef = payloadRef; }

    public String getObservedAt() { return observedAt; }
    public void setObservedAt(String observedAt) { this.observedAt = observedAt; }
}