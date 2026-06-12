package com.sslproxy.coordinator.oracle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sslproxy.coordinator.config.CoordinatorProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Component
public class OraclePayloadResolver {

    private final String syncOutboxDir;
    private final ObjectMapper objectMapper;

    public OraclePayloadResolver(CoordinatorProperties props, ObjectMapper objectMapper) {
        this.syncOutboxDir = props.syncOutboxDir();
        this.objectMapper = objectMapper;
    }

    OraclePayloadResolver(String syncOutboxDir, ObjectMapper objectMapper) {
        this.syncOutboxDir = syncOutboxDir;
        this.objectMapper = objectMapper;
    }

    public String resolvePayload(String payloadRef) {
        String ref = payloadRef == null ? "" : payloadRef;
        if (ref.startsWith("inline://json/")) {
            String encoded = ref.substring("inline://json/".length());
            byte[] bytes = Base64.getUrlDecoder().decode(paddedBase64(encoded));
            String payload = new String(bytes, StandardCharsets.UTF_8);
            validateJson(payload);
            return payload;
        }

        if (ref.startsWith("outbox://")) {
            return resolveOutbox(ref.substring("outbox://".length()));
        }

        throw new IllegalArgumentException("unsupported payload_ref scheme: " + ref);
    }

    public List<JsonNode> payloadRows(OracleSinkTarget target, String payload) {
        JsonNode value = parse(payload);
        List<JsonNode> specialRows = probeRows(target, value);
        if (specialRows != null) {
            return specialRows;
        }
        specialRows = clientInventoryRows(target, value);
        if (specialRows != null) {
            return specialRows;
        }

        if (value.isArray()) {
            List<JsonNode> rows = new ArrayList<>(value.size());
            value.forEach(rows::add);
            return List.copyOf(rows);
        }
        return List.of(value);
    }

    private String resolveOutbox(String relativePath) {
        try {
            Path outboxBase = Path.of(syncOutboxDir).toRealPath();
            Path resolved = outboxBase.resolve(relativePath).normalize().toRealPath();
            if (!resolved.startsWith(outboxBase)) {
                throw new IllegalArgumentException("invalid outbox path escapes base: " + resolved);
            }
            String payload = Files.readString(resolved);
            validateJson(payload);
            return payload;
        } catch (IOException e) {
            throw new IllegalArgumentException("resolve outbox path " + relativePath + ": " + e.getMessage(), e);
        }
    }

    private List<JsonNode> probeRows(OracleSinkTarget target, JsonNode value) {
        if (target != OracleSinkTarget.WIRELESS_PROBE_REQUESTS) {
            return null;
        }
        JsonNode probes = value.get("probes");
        if (probes == null || !probes.isArray()) {
            return null;
        }
        List<JsonNode> rows = new ArrayList<>(probes.size());
        probes.forEach(rows::add);
        return List.copyOf(rows);
    }

    private List<JsonNode> clientInventoryRows(OracleSinkTarget target, JsonNode value) {
        if (target != OracleSinkTarget.WIRELESS_CLIENT_INVENTORY) {
            return null;
        }
        JsonNode clients = value.get("clients");
        if (clients == null || !clients.isArray()) {
            return null;
        }
        List<JsonNode> rows = new ArrayList<>(clients.size());
        for (JsonNode client : clients) {
            if (!client.isObject()) {
                throw new IllegalArgumentException("wireless client inventory clients must contain objects");
            }
            var merged = objectMapper.createObjectNode();
            merged.setAll((com.fasterxml.jackson.databind.node.ObjectNode) client);
            copyIfPresent(value, merged, "sensor_id");
            copyIfPresent(value, merged, "location_id");
            JsonNode snapshotAt = value.has("snapshot_at") ? value.get("snapshot_at") : value.get("observed_at");
            if (snapshotAt != null) {
                merged.set("snapshot_at", snapshotAt);
            }
            rows.add(merged);
        }
        return List.copyOf(rows);
    }

    private void copyIfPresent(JsonNode source, com.fasterxml.jackson.databind.node.ObjectNode target, String field) {
        JsonNode value = source.get(field);
        if (value != null) {
            target.set(field, value);
        }
    }

    private void validateJson(String payload) {
        parse(payload);
    }

    private JsonNode parse(String payload) {
        try {
            return objectMapper.readTree(payload);
        } catch (IOException e) {
            throw new IllegalArgumentException("payload_ref resolved non-JSON payload: " + e.getMessage(), e);
        }
    }

    private String paddedBase64(String encoded) {
        int remainder = encoded.length() % 4;
        if (remainder == 0) {
            return encoded;
        }
        return encoded + "=".repeat(4 - remainder);
    }
}
