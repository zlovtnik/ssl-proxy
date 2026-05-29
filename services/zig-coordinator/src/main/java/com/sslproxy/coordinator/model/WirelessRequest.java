package com.sslproxy.coordinator.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a wireless request that may contain an optional reply_topic.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class WirelessRequest {

    private String operation;

    @JsonProperty("reply_topic")
    private String replyTopic;

    public String getOperation() { return operation; }
    public void setOperation(String operation) { this.operation = operation; }

    public String getReplyTopic() { return replyTopic; }
    public void setReplyTopic(String replyTopic) { this.replyTopic = replyTopic; }
}