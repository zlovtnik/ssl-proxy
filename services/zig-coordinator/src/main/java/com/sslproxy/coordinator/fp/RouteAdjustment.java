package com.sslproxy.coordinator.fp;

public sealed interface RouteAdjustment permits
        RouteAdjustment.NoChange,
        RouteAdjustment.Shrink,
        RouteAdjustment.Restore {

    record NoChange(String reason) implements RouteAdjustment {}

    record Shrink(int newMaxPollRecords, long pendingCount, long upperThreshold) implements RouteAdjustment {}

    record Restore(int newMaxPollRecords, long pendingCount, long lowerThreshold) implements RouteAdjustment {}
}
