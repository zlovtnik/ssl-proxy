package com.sslproxy.coordinator.fp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DbResultTest {

    @Test
    void ofCapturesRuntimeExceptionAsErr() {
        DbResult<String> result = DbResult.of(() -> {
            throw new RuntimeException("boom");
        }, "test.op");

        DbResult.Err<?> err = assertInstanceOf(DbResult.Err.class, result);
        assertEquals("test.op", err.operation());
    }

    @Test
    void ofMapsNullToEmpty() {
        DbResult<String> result = DbResult.of(() -> null, "test.empty");

        assertInstanceOf(DbResult.Empty.class, result);
        assertTrue(result.toOptional().isEmpty());
    }

    @Test
    void switchExpressionIsExhaustive() {
        List<DbResult<String>> results = List.of(
                new DbResult.Ok<>("value"),
                new DbResult.Empty<>(),
                new DbResult.Err<>("op", new RuntimeException("boom"))
        );

        for (DbResult<String> result : results) {
            String label = switch (result) {
                case DbResult.Ok<String> ignored -> "ok";
                case DbResult.Empty<String> ignored -> "empty";
                case DbResult.Err<String> ignored -> "err";
            };
            assertTrue(!label.isEmpty());
        }
    }
}
