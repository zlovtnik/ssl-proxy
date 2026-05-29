package com.sslproxy.coordinator.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 hashing utilities matching the Zig sha256Hex function.
 */
public final class Sha256Utils {

    private Sha256Utils() {}

    /**
     * Computes SHA-256 hex digest.
     */
    public static String sha256Hex(byte[] payload) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Computes SHA-256 hex digest of a UTF-8 string.
     */
    public static String sha256Hex(String payload) {
        return sha256Hex(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}