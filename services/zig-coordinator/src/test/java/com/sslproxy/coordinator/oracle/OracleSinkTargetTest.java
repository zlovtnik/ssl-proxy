package com.sslproxy.coordinator.oracle;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OracleSinkTargetTest {

    @Test
    void mapsLegacyAndCurrentWirelessStreamNamesToCanonicalTargets() {
        assertEquals(OracleSinkTarget.PROXY_PAYLOAD_AUDIT,
                OracleSinkTarget.fromStreamName("proxy.payload_audit").orElseThrow());
        assertEquals(OracleSinkTarget.WIRELESS_ROGUE_AP,
                OracleSinkTarget.fromStreamName("wireless.rogue_ap").orElseThrow());
        assertEquals(OracleSinkTarget.WIRELESS_ROGUE_AP,
                OracleSinkTarget.fromStreamName("wireless.alert.rogue_ap").orElseThrow());
        assertEquals(OracleSinkTarget.WIRELESS_CLIENT_INVENTORY,
                OracleSinkTarget.fromStreamName("wireless.client_inventory").orElseThrow());
        assertEquals(OracleSinkTarget.WIRELESS_CLIENT_INVENTORY,
                OracleSinkTarget.fromStreamName("wireless.client.inventory").orElseThrow());
        assertTrue(OracleSinkTarget.fromStreamName("unknown").isEmpty());
    }

    @Test
    void checksumIncludesCanonicalSinkTagAndPayload() {
        assertEquals(
                "638b6b3e36b3a233d9ced00e60b016266a098f713eb7241353ede61c4c148020",
                OracleChecksum.checksum(OracleSinkTarget.PROXY_EVENTS, "{\"ok\":true}")
        );
    }
}
