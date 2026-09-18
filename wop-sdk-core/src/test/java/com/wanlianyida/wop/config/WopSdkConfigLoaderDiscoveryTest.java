package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopClient;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** config-spec §4.2：发现顺序与显式不可读 fail-fast。 */
class WopSdkConfigLoaderDiscoveryTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        WopSdkConfigLoader.clearCache();
        WopClient.resetDefault();
    }

    private String validJson(String appKey) {
        return "{"
                + "\"appKey\":\"" + appKey + "\","
                + "\"suite\":\"WOP-RSA3072-SHA256\","
                + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                + "\"serverRoot\":\"https://gw.example.com/gateway\","
                + "\"expiredSeconds\":1800"
                + "}";
    }

    @Test
    void explicitSysPropUnreadableFailsFastWithoutFallback() {
        System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY,
                tempDir.resolve("missing.json").toString());
        WopError error = assertThrows(WopError.class, WopSdkConfigLoader::loadDefault);
        assertTrue(error.getMessage().contains("显式配置文件不可读"));
    }

    @Test
    void explicitSysPropReadableLoadsThatFile() throws Exception {
        Path file = tempDir.resolve("explicit.json");
        Files.write(file, validJson("from_sysprop").getBytes(StandardCharsets.UTF_8));
        System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, file.toString());
        WopSdkConfig cfg = WopSdkConfigLoader.loadDefault();
        assertEquals("from_sysprop", cfg.appKey());
    }

    @Test
    void loadPathUsesFileSystem() throws Exception {
        Path file = tempDir.resolve("manual.json");
        Files.write(file, validJson("from_path").getBytes(StandardCharsets.UTF_8));
        WopSdkConfig cfg = WopSdkConfigLoader.load(file);
        assertEquals("from_path", cfg.appKey());
    }

    @Test
    void loadClasspathPrefixFromTestResource() throws Exception {
        Path configDir = tempDir.resolve("config");
        Files.createDirectories(configDir);
        Files.write(configDir.resolve("test.json"),
                validJson("classpath_app").getBytes(StandardCharsets.UTF_8));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                WopSdkConfigLoaderDiscoveryTest.class.getClassLoader())) {
            Thread current = Thread.currentThread();
            ClassLoader original = current.getContextClassLoader();
            current.setContextClassLoader(cl);
            try {
                WopSdkConfig cfg = WopSdkConfigLoader.load("classpath:config/test.json");
                assertEquals("classpath_app", cfg.appKey());
            } finally {
                current.setContextClassLoader(original);
            }
        }
    }

    @Test
    void duplicateServerRootKeyFailsFast() {
        String json = "{"
                + "\"appKey\":\"a\","
                + "\"suite\":\"WOP-RSA3072-SHA256\","
                + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                + "\"serverRoot\":\"https://gw.example.com/gateway\","
                + "\"serverRoot\":\"https://other.example.com/gateway\""
                + "}";
        WopError error = assertThrows(WopError.class, () -> ConfigJsonParser.parse(json));
        assertTrue(error.getMessage().contains("serverRoot"));
        assertTrue(error.getMessage().contains("重复"));
    }

    @Test
    void backupServerRootHttpsValidation() {
        String json = "{"
                + "\"appKey\":\"a\","
                + "\"suite\":\"WOP-RSA3072-SHA256\","
                + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                + "\"serverRoot\":\"https://gw.example.com/gateway\","
                + "\"backupServerRoots\":[\"http://insecure.example.com/gateway\"]"
                + "}";
        WopError error = assertThrows(WopError.class, () -> ConfigJsonParser.parse(json));
        assertTrue(error.getMessage().contains("backupServerRoots[0]"));
        assertTrue(error.getMessage().contains("HTTPS"));
    }
}
