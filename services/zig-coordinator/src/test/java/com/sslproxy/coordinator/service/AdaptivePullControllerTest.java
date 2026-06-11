package com.sslproxy.coordinator.service;

import com.sslproxy.coordinator.fp.RouteAdjustment;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdaptivePullControllerTest {

    @Test
    void shrinkNeverGoesBelowMinimumPullRecords() {
        RouteAdjustment result = AdaptivePullController.decideAdjustment(
                10_000,
                1_000,
                500,
                500,
                500,
                10,
                30_000,
                10_000
        );

        RouteAdjustment.Shrink shrink = assertInstanceOf(RouteAdjustment.Shrink.class, result);
        assertTrue(shrink.newMaxPollRecords() >= 50);
    }

    @Test
    void restoreReturnsConfiguredFetchCount() {
        RouteAdjustment result = AdaptivePullController.decideAdjustment(
                100,
                1_000,
                750,
                50,
                50,
                1,
                30_000,
                10_000
        );

        RouteAdjustment.Restore restore = assertInstanceOf(RouteAdjustment.Restore.class, result);
        assertEquals(750, restore.newMaxPollRecords());
    }

    @Test
    void hysteresisSuppressesSmallChangesInsideRestartWindow() {
        RouteAdjustment result = AdaptivePullController.decideAdjustment(
                850,
                1_000,
                500,
                500,
                150,
                200,
                1_000,
                10_000
        );

        RouteAdjustment.NoChange noChange = assertInstanceOf(RouteAdjustment.NoChange.class, result);
        assertEquals("hysteresis", noChange.reason());
    }
}
