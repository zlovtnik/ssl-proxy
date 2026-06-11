package com.sslproxy.coordinator.fp;

import java.util.List;
import java.util.stream.IntStream;

public final class FpUtils {

    private FpUtils() {}

    public static <T> List<List<T>> partition(List<T> list, int size) {
        if (size < 1) {
            throw new IllegalArgumentException("size must be positive");
        }
        return IntStream.range(0, (list.size() + size - 1) / size)
                .mapToObj(i -> List.copyOf(list.subList(i * size, Math.min((i + 1) * size, list.size()))))
                .toList();
    }
}
