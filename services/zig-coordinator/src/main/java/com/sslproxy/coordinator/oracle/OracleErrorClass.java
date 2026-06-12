package com.sslproxy.coordinator.oracle;

import java.util.Locale;

public enum OracleErrorClass {
    RETRYABLE("retryable"),
    PERMANENT("permanent");

    private final String wireValue;

    OracleErrorClass(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static OracleErrorClass classify(String message) {
        String normalized = message == null ? "" : message.toLowerCase(Locale.ROOT);
        if (normalized.contains("timeout")
                || normalized.contains("dpi-1067")
                || normalized.contains("ora-03114")
                || normalized.contains("ora-03136")
                || normalized.contains("ora-3136")
                || normalized.contains("temporarily unavailable")
                || normalized.contains("connection reset")
                || normalized.contains("deadlock")) {
            return RETRYABLE;
        }
        return PERMANENT;
    }
}
