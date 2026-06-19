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
        String loadRoute = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/route/OracleLoadRoute.java"));
        String payloadAuditRoute = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/route/PayloadAuditRoute.java"));
        String scanProcessor = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/processor/ScanRecordProcessor.java"));
        String payloadAuditProcessor = Files.readString(Path.of("src/main/java/com/sslproxy/coordinator/processor/PayloadAuditRecordProcessor.java"));

        assertFalse(scanRoute.contains("${body}"));
        assertFalse(resultRoute.contains("${body}"));
        assertFalse(loadRoute.contains("${body}"));
        assertFalse(payloadAuditRoute.contains("${body}"));
        assertFalse(scanProcessor.contains("body" + "={}"));
        assertFalse(payloadAuditProcessor.contains("body" + "={}"));
    }
}
