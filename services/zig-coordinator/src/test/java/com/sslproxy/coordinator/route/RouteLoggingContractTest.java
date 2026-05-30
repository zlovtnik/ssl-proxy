package com.sslproxy.coordinator.route;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;

class RouteLoggingContractTest {

    @Test
    void scanAndResultRoutesDoNotLogMessageBodies() throws Exception {
        String scanRoute = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/route/ScanRequestRoute.java"));
        String resultRoute = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/route/OracleResultRoute.java"));
        String scanProcessor = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/processor/ScanRecordProcessor.java"));

        assertFalse(scanRoute.contains("${body}"));
        assertFalse(resultRoute.contains("${body}"));
        assertFalse(scanProcessor.contains("body" + "={}"));
    }
}
