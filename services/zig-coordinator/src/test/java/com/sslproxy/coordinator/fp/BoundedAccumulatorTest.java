package com.sslproxy.coordinator.fp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BoundedAccumulatorTest {

    @Test
    void drainIsIdempotentOnEmptyAccumulator() {
        BoundedAccumulator<String> accumulator = new BoundedAccumulator<>("test", 100);

        assertTrue(accumulator.drain(50).isEmpty());
        assertTrue(accumulator.drain(50).isEmpty());
    }

    @Test
    void requeueFrontPreservesOrderUpToCapacity() {
        BoundedAccumulator<Integer> accumulator = new BoundedAccumulator<>("test", 5);

        int dropped = accumulator.requeueFront(List.of(1, 2, 3));

        assertEquals(0, dropped);
        assertEquals(List.of(1, 2, 3), accumulator.drain(10));
    }

    @Test
    void offerDropsWhenFull() {
        BoundedAccumulator<String> accumulator = new BoundedAccumulator<>("test", 2);

        assertTrue(accumulator.offer("a"));
        assertTrue(accumulator.offer("b"));
        assertFalse(accumulator.offer("c"));
        assertEquals(2, accumulator.size());
    }

    @Test
    void requeueFrontDropsItemsThatCannotBeOffered() {
        BoundedAccumulator<Integer> accumulator = new BoundedAccumulator<>("test", 2);

        int dropped = accumulator.requeueFront(List.of(1, 2, 3));

        assertEquals(1, dropped);
        assertEquals(List.of(2, 3), accumulator.drain(10));
    }
}
