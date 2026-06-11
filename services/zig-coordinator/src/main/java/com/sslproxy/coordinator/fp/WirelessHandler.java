package com.sslproxy.coordinator.fp;

@FunctionalInterface
public interface WirelessHandler {
    String handle(String payload) throws Exception;
}
