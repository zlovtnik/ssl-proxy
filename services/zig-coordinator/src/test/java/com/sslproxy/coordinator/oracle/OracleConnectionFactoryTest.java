package com.sslproxy.coordinator.oracle;

import com.sslproxy.coordinator.config.OracleSinkProperties;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OracleConnectionFactoryTest {

    @Test
    void validatesAutoLoginWalletAndAlias(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        writeWallet(wallet, "mainerc_high");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(wallet, passFile, "mainerc_high"));

        OracleConnectionFactory.OracleConfiguration configuration = factory.validateConfiguration();

        assertEquals(wallet, configuration.tnsAdmin());
        assertEquals("secret", configuration.password());
    }

    @Test
    void rejectsMissingWalletArtifact(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        Files.createDirectories(wallet);
        Files.writeString(wallet.resolve("tnsnames.ora"), "mainerc_high = (description=ok)");
        Files.writeString(wallet.resolve("sqlnet.ora"), "WALLET_LOCATION = ok");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(wallet, passFile, "mainerc_high"));

        IllegalStateException error = assertThrows(IllegalStateException.class, factory::validateConfiguration);

        assertTrue(error.getMessage().contains("missing Oracle wallet artifact"));
        assertTrue(error.getMessage().contains("cwallet.sso"));
        assertTrue(error.getMessage().contains("wallet diagnostics"));
        assertTrue(error.getMessage().contains("tnsnames.ora{regular=true"));
        assertTrue(error.getMessage().contains("sqlnet.ora{regular=true"));
    }

    @Test
    void startupValidationRejectsMissingWalletArtifact(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        Files.createDirectories(wallet);
        Files.writeString(wallet.resolve("sqlnet.ora"), "WALLET_LOCATION = ok");
        Files.writeString(wallet.resolve("cwallet.sso"), "wallet");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(wallet, passFile, "mainerc_high"));

        IllegalStateException error = assertThrows(IllegalStateException.class, factory::validateStartupConfiguration);

        assertTrue(error.getMessage().contains("missing Oracle wallet artifact"));
        assertTrue(error.getMessage().contains("tnsnames.ora"));
        assertTrue(error.getMessage().contains("wallet diagnostics"));
    }

    @Test
    void rejectsMissingTnsAlias(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        writeWallet(wallet, "mainerc_low");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(wallet, passFile, "mainerc_high"));

        IllegalStateException error = assertThrows(IllegalStateException.class, factory::validateConfiguration);

        assertTrue(error.getMessage().contains("Oracle TNS alias not found"));
        assertTrue(error.getMessage().contains("mainerc_high"));
    }

    @Test
    void validatesSimpleAliasFromJdbcUrl(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        writeWallet(wallet, "mainerc_high");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(
                wallet,
                passFile,
                "",
                "jdbc:oracle:thin:@mainerc_high"
        ));

        OracleConnectionFactory.OracleConfiguration configuration = factory.validateConfiguration();

        assertEquals(wallet, configuration.tnsAdmin());
    }

    @Test
    void allowsFullJdbcDescriptorWithoutAliasValidation(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        writeWallet(wallet, "mainerc_low");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(
                wallet,
                passFile,
                "",
                "jdbc:oracle:thin:@(description=(connect_data=(service_name=example)))"
        ));

        OracleConnectionFactory.OracleConfiguration configuration = factory.validateConfiguration();

        assertEquals(wallet, configuration.tnsAdmin());
    }

    @Test
    void rejectsMissingAliasFromSimpleJdbcUrl(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        writeWallet(wallet, "mainerc_low");
        Files.writeString(passFile, "secret\n");

        OracleConnectionFactory factory = factory(props(
                wallet,
                passFile,
                "",
                "jdbc:oracle:thin:@mainerc_high"
        ));

        IllegalStateException error = assertThrows(IllegalStateException.class, factory::validateConfiguration);

        assertTrue(error.getMessage().contains("Oracle TNS alias not found"));
        assertTrue(error.getMessage().contains("mainerc_high"));
    }

    @Test
    void rejectsBlankPasswordFile(@TempDir Path root) throws Exception {
        Path wallet = root.resolve("wallet");
        Path passFile = root.resolve("oracle-password.txt");
        writeWallet(wallet, "mainerc_high");
        Files.writeString(passFile, "\n");

        OracleConnectionFactory factory = factory(props(wallet, passFile, "mainerc_high"));

        IllegalStateException error = assertThrows(IllegalStateException.class, factory::validateConfiguration);

        assertTrue(error.getMessage().contains("Oracle password file is empty"));
    }

    @Test
    void closeIsIdempotent() throws Exception {
        OracleConnectionFactory factory = factory(props(Path.of("/tmp/wallet"), Path.of("/tmp/pass"), "mainerc_high"));
        HikariDataSource dataSource = mock(HikariDataSource.class);
        when(dataSource.isClosed()).thenReturn(false, true);
        when(dataSource.getPoolName()).thenReturn("oracle-sink");
        Field field = OracleConnectionFactory.class.getDeclaredField("dataSource");
        field.setAccessible(true);
        field.set(factory, dataSource);

        assertDoesNotThrow(factory::close);
        assertDoesNotThrow(factory::close);

        verify(dataSource, times(1)).close();
    }

    private void writeWallet(Path wallet, String alias) throws Exception {
        Files.createDirectories(wallet);
        Files.writeString(wallet.resolve("tnsnames.ora"), alias + " = (description=ok)\n");
        Files.writeString(wallet.resolve("sqlnet.ora"), "WALLET_LOCATION = ok\n");
        Files.writeString(wallet.resolve("cwallet.sso"), "wallet");
    }

    private OracleSinkProperties props(Path wallet, Path passFile, String conn) {
        return props(wallet, passFile, conn, "");
    }

    private OracleSinkProperties props(Path wallet, Path passFile, String conn, String jdbcUrl) {
        return new OracleSinkProperties(
                true,
                true,
                false,
                conn,
                jdbcUrl,
                "USCIS_APP",
                passFile.toString(),
                wallet.toString(),
                1,
                0,
                1_000,
                1_000,
                1_000,
                1_000,
                30_000,
                "SELECT 1 FROM DUAL",
                5,
                3
        );
    }

    private OracleConnectionFactory factory(OracleSinkProperties props) {
        return new OracleConnectionFactory(props, new SimpleMeterRegistry());
    }
}
