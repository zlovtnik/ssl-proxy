package com.sslproxy.coordinator.processor;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Resolves payload references from scan requests.
 * Supports:
 * - inline://json/<base64url-encoded JSON>
 * - outbox://<relative file path in outbox directory>
 *
 * Corresponds to sync_handlers.zig resolvePayloadRef()
 */
@Component
public class PayloadResolver {

    private static final Logger log = LoggerFactory.getLogger(PayloadResolver.class);
    private static final String INLINE_PREFIX = "inline://json/";
    private static final String OUTBOX_PREFIX = "outbox://";
    private static final long MAX_PAYLOAD_BYTES = 16 * 1024 * 1024; // 16 MB

    private final ObjectMapper objectMapper;

    public PayloadResolver(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Resolves a payload reference to its byte content.
     *
     * @param payloadRef the payload reference (e.g., "inline://json/...", "outbox://...")
     * @param outboxDir  the base outbox directory for outbox references
     * @return the resolved payload bytes
     * @throws IllegalArgumentException if the reference cannot be resolved
     */
    public byte[] resolve(String payloadRef, String outboxDir) {
        if (payloadRef == null || payloadRef.isEmpty()) {
            throw new IllegalArgumentException("Empty payload reference");
        }

        if (payloadRef.startsWith(INLINE_PREFIX)) {
            String encoded = payloadRef.substring(INLINE_PREFIX.length());
            byte[] decoded;
            try {
                decoded = Base64.getUrlDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                log.error("Invalid inline payload encoding: {}", e.getMessage());
                throw new IllegalArgumentException("Invalid inline payload encoding", e);
            }
            validateJson(decoded);
            return decoded;
        }

        if (payloadRef.startsWith(OUTBOX_PREFIX)) {
            String locator = payloadRef.substring(OUTBOX_PREFIX.length());
            if (!isSafeOutboxLocator(locator)) {
                throw new IllegalArgumentException("Unsafe outbox locator: " + locator);
            }
            try {
                Path outboxPath = Paths.get(outboxDir).toAbsolutePath().normalize();
                Path filePath = outboxPath.resolve(locator).normalize();

                // Ensure the resolved path is still within the outbox directory
                if (!filePath.startsWith(outboxPath)) {
                    throw new IllegalArgumentException("Path traversal detected: " + locator);
                }

                Path realOutboxPath = outboxPath.toRealPath();
                if (!Files.exists(filePath) || !Files.isReadable(filePath)) {
                    throw new IllegalArgumentException("Outbox file not found or not readable: " + locator);
                }
                Path realFilePath = filePath.toRealPath();
                if (!realFilePath.startsWith(realOutboxPath)) {
                    throw new IllegalArgumentException("Path traversal detected: " + locator);
                }
                if (!Files.isReadable(realFilePath)) {
                    throw new IllegalArgumentException("Outbox file not readable: " + locator);
                }

                long fileSize = Files.size(realFilePath);
                if (fileSize > MAX_PAYLOAD_BYTES) {
                    throw new IllegalArgumentException("Outbox file too large: " + fileSize + " bytes");
                }

                byte[] payload = Files.readAllBytes(realFilePath);
                validateJson(payload);
                return payload;
            } catch (IOException e) {
                log.error("Failed to read outbox payload: {}", e.getMessage());
                throw new IllegalArgumentException("Outbox read failed: " + locator, e);
            }
        }

        throw new IllegalArgumentException("Unknown payload reference scheme: " + payloadRef);
    }

    /**
     * Validates that the payload is valid JSON.
     */
    private void validateJson(byte[] payload) {
        try {
            objectMapper.readTree(payload);
        } catch (IOException e) {
            throw new IllegalArgumentException("Payload is not valid JSON", e);
        }
    }

    /**
     * Checks that an outbox locator is safe (no path traversal, no absolute paths).
     */
    static boolean isSafeOutboxLocator(String locator) {
        if (locator == null || locator.isEmpty()) return false;
        if (locator.startsWith("/")) return false;
        if (locator.contains("\\")) return false;

        String normalized = locator.replace('\\', '/');
        String[] parts = normalized.split("/");
        for (String part : parts) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                return false;
            }
        }
        return true;
    }
}
