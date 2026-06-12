package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OraclePayloadResolverTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void resolvesInlineUrlSafeJsonPayload() {
        OraclePayloadResolver resolver = new OraclePayloadResolver("/tmp", objectMapper);
        String payload = "{\"type\":\"audit\",\"host\":\"example.com\"}";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        assertEquals(payload, resolver.resolvePayload("inline://json/" + encoded));
    }

    @Test
    void resolvesOutboxPayloadUnderBase(@TempDir Path root) throws Exception {
        Path outbox = root.resolve("outbox");
        Files.createDirectories(outbox);
        Files.writeString(outbox.resolve("payload.json"), "{\"ok\":true}");

        OraclePayloadResolver resolver = new OraclePayloadResolver(outbox.toString(), objectMapper);

        assertEquals("{\"ok\":true}", resolver.resolvePayload("outbox://payload.json"));
    }

    @Test
    void rejectsOutboxTraversal(@TempDir Path root) throws Exception {
        Path outbox = root.resolve("outbox");
        Files.createDirectories(outbox);
        Files.writeString(root.resolve("outside.json"), "{\"escaped\":true}");
        OraclePayloadResolver resolver = new OraclePayloadResolver(outbox.toString(), objectMapper);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> resolver.resolvePayload("outbox://../outside.json"));

        assertEquals(true, error.getMessage().contains("invalid outbox path escapes base"));
    }

    @Test
    void rejectsProbeEnvelopeWithoutProbesArray() {
        OraclePayloadResolver resolver = new OraclePayloadResolver("/tmp", objectMapper);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> resolver.payloadRows(OracleSinkTarget.WIRELESS_PROBE_REQUESTS, "{\"clients\":[]}"));

        assertEquals(true, error.getMessage().contains("probes array"));
    }

    @Test
    void rejectsClientInventoryEnvelopeWithoutClientsArray() {
        OraclePayloadResolver resolver = new OraclePayloadResolver("/tmp", objectMapper);

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> resolver.payloadRows(OracleSinkTarget.WIRELESS_CLIENT_INVENTORY, "{\"probes\":[]}"));

        assertEquals(true, error.getMessage().contains("clients array"));
    }
}
