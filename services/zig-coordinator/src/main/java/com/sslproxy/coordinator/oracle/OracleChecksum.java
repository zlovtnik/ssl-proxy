package com.sslproxy.coordinator.oracle;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class OracleChecksum {

    private OracleChecksum() {}

    static String checksum(OracleSinkTarget target, String payload) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(target.checksumTag().getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest unavailable", e);
        }
    }
}
