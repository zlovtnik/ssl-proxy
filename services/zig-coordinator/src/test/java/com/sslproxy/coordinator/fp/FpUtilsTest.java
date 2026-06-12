package com.sslproxy.coordinator.fp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FpUtilsTest {

    @Test
    void partitionReturnsIndependentImmutableCopies() {
        List<String> items = new ArrayList<>(List.of("a", "b", "c"));

        List<List<String>> partitions = FpUtils.partition(items, 2);
        items.set(0, "changed");

        assertEquals(List.of("a", "b"), partitions.get(0));
        assertEquals(List.of("c"), partitions.get(1));
        assertThrows(UnsupportedOperationException.class, () -> partitions.get(0).add("d"));
    }
}
