package com.sslproxy.coordinator.oracle;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OracleSchemaContractTest {

    @Test
    void blockchainTablesUsePortableRetentionAndDatatypes() throws Exception {
        String sql = readOracleSql();

        assertEquals(3, countMatches(sql, "NO DROP UNTIL 16 DAYS IDLE"),
                "blockchain tables should not require TABLE RETENTION privilege");
        assertFalse(sql.contains("NO DROP UNTIL 365 DAYS IDLE"),
                "non-privileged Oracle users are capped below 365 idle retention days");

        assertBlockchainTableHasNoTimezoneColumns(sql, "PROXY_PAYLOAD_AUDIT");
        assertBlockchainTableHasNoTimezoneColumns(sql, "PROXY_BLOCKLIST_AUDIT");
        assertBlockchainTableHasNoTimezoneColumns(sql, "WIRELESS_ALERTS_LEDGER");
    }

    @Test
    void wirelessAlertsLedgerStoresDetectedAtAsUtcTimestamp() throws Exception {
        String sql = readOracleSql();

        assertTrue(sql.contains("CAST(SYS_EXTRACT_UTC(:NEW.DETECTED_AT) AS TIMESTAMP)"),
                "blockchain ledger must convert source TIMESTAMP WITH TIME ZONE values to UTC TIMESTAMP");
    }

    @Test
    void wirelessChannelPrimaryKeySupportsRelyForeignKeys() throws Exception {
        String sql = readOracleSql();

        assertTrue(sql.contains(
                        "CONSTRAINT WIRELESS_CHANNELS_PK PRIMARY KEY (CHANNEL, BAND) RELY"),
                "RELY wireless foreign keys require the referenced primary key to be RELY");
    }

    @Test
    void ilmPoliciesUseSupportedActionsOnly() throws Exception {
        String sql = readOracleSql();

        assertFalse(sql.contains("ILM ADD POLICY\n    DROP PARTITION"),
                "Oracle ADO ILM does not accept DROP PARTITION as a policy action");
        assertTrue(sql.contains("ILM ADD POLICY\n    ROW STORE COMPRESS ADVANCED ROW"),
                "compression ADO policies should remain in the baseline");
    }

    @Test
    void requiredProceduresDoNotNeedDbmsLockGrant() throws Exception {
        String sql = readOracleSql();

        assertFalse(sql.contains("DBMS_LOCK"),
                "startup-required procedures should compile without security-admin DBMS_LOCK grants");
    }

    private void assertBlockchainTableHasNoTimezoneColumns(String sql, String tableName) {
        String block = blockchainTableBlock(sql, tableName);

        assertFalse(block.contains("TIMESTAMP WITH TIME ZONE"),
                tableName + " must avoid timezone columns unsupported by blockchain tables");
    }

    private String blockchainTableBlock(String sql, String tableName) {
        int start = sql.indexOf("CREATE BLOCKCHAIN TABLE " + tableName);
        assertTrue(start >= 0, "expected blockchain table " + tableName);

        int end = sql.indexOf("HASHING USING SHA2_512 VERSION V1;", start);
        assertTrue(end > start, "expected blockchain table options for " + tableName);

        return sql.substring(start, end);
    }

    private int countMatches(String sql, String needle) {
        return (int) Pattern.compile(Pattern.quote(needle)).matcher(sql).results().count();
    }

    private String readOracleSql() throws Exception {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null) {
            Path candidate = current.resolve("sql/oracle.sql");
            if (Files.isRegularFile(candidate)) {
                return Files.readString(candidate);
            }
            current = current.getParent();
        }
        throw new IllegalStateException("Unable to locate sql/oracle.sql from " + System.getProperty("user.dir"));
    }
}
