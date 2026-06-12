package com.sslproxy.coordinator.oracle;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OracleErrorClassTest {

    @Test
    void classifyIsStableUnderTurkishLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr"));

            assertEquals(OracleErrorClass.RETRYABLE, OracleErrorClass.classify("DPI-1067 connection reset"));
        } finally {
            Locale.setDefault(original);
        }
    }
}
