package com.sslproxy.coordinator.fp;

@FunctionalInterface
public interface CheckedConsumer<T> {
    void accept(T value) throws Exception;
}
