package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopClient;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** config-spec P0：Loader、解析、校验、缓存与 path 规则。 */
class WopSdkConfigLoaderTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        WopSdkConfigLoader.clearCache();
        WopClient.resetDefault();
    }

    private String validConfigJson(String overrides) {
        String base = "{"
                + "\"appKey\":\"app_001\","
                + "\"suite\":\"WOP-RSA3072-SHA256\","
                + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                + "\"serverRoot\":\"https://gw.example.com/gateway\","
                + "\"backupServerRoots\":[\"https://gw-backup.example.com/gateway\"],"
                + "\"expiredSeconds\":1800,"
                + "\"httpClient\":{\"connectTimeout\":10000,\"readTimeout\":30000,\"maxRetryCount\":3}"
                + "}";
        if (overrides == null) {
            return base;
        }
        return overrides;
    }

    private Path writeConfig(String json) throws Exception {
        Path file = tempDir.resolve("wopSdkConfig.json");
        Files.write(file, json.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    @Test
    void parseNormalizesServerRootTrailingSlash() throws Exception {
        String json = validConfigJson(null).replace(
                "https://gw.example.com/gateway",
                "https://gw.example.com/gateway/");
        WopSdkConfig cfg = WopSdkConfigLoader.load(writeConfig(json));
        assertEquals("https://gw.example.com/gateway", cfg.serverRoot());
        assertEquals(10_000, cfg.httpClient().connectTimeout());
    }

    @Test
    void duplicateKeyFailsFast() {
        WopError error = assertThrows(WopError.class, () -> ConfigJsonParser.parse(
                "{\"appKey\":\"a\",\"appKey\":\"b\",\"suite\":\"WOP-RSA3072-SHA256\"}"));
        assertTrue(error.getMessage().contains("配置字段 appKey 重复"));
        assertEquals(WopError.Category.configuration, error.category());
    }

    @Test
    void missingAppKeyFailsFast() {
        String json = "{"
                + "\"suite\":\"WOP-RSA3072-SHA256\","
                + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                + "\"serverRoot\":\"https://gw.example.com/gateway\""
                + "}";
        WopError error = assertThrows(WopError.class, () -> WopSdkConfigLoader.load(writeConfig(json)));
        assertTrue(error.getMessage().contains("缺少必填项: appKey"));
    }

    @Test
    void loadSamePathReturnsSameInstance() throws Exception {
        Path file = writeConfig(validConfigJson(null));
        WopSdkConfig a = WopSdkConfigLoader.load(file);
        WopSdkConfig b = WopSdkConfigLoader.load(file);
        assertSame(a, b);
    }

    @Test
    void clearCacheReloads() throws Exception {
        Path file = writeConfig(validConfigJson(null));
        WopSdkConfig first = WopSdkConfigLoader.load(file);
        WopSdkConfigLoader.clearCache();
        Files.write(file, validConfigJson(null).replace("app_001", "app_002")
                .getBytes(StandardCharsets.UTF_8));
        WopSdkConfig second = WopSdkConfigLoader.load(file);
        assertEquals("app_001", first.appKey());
        assertEquals("app_002", second.appKey());
        assertNotSame(first, second);
    }

    @Test
    void validateApiPathRejectsDoubleSlash() {
        WopError error = assertThrows(WopError.class,
                () -> ConfigUrlUtils.validateApiPath("//attacker.example/path"));
        assertTrue(error.getMessage().contains("// 开头"));
    }

    @Test
    void validateApiPathRejectsAbsoluteUrlAndQuery() {
        WopError abs = assertThrows(WopError.class,
                () -> ConfigUrlUtils.validateApiPath("http://evil.example/path"));
        assertTrue(abs.getMessage().contains("须以 / 开头") || abs.getMessage().contains("绝对 URL"));
        WopError query = assertThrows(WopError.class,
                () -> ConfigUrlUtils.validateApiPath("/gateway/x?a=1"));
        assertTrue(query.getMessage().contains("query"));
    }

    @Test
    void validateGatewayUrlRejectsQueryAndFragment() {
        WopError query = assertThrows(WopError.class, () -> ConfigUrlUtils.validateGatewayUrl(
                "https://gw.example.com/gateway?x=1", "serverRoot"));
        assertTrue(query.getMessage().contains("query"));
        WopError fragment = assertThrows(WopError.class, () -> ConfigUrlUtils.validateGatewayUrl(
                "https://gw.example.com/gateway#x", "serverRoot"));
        assertTrue(fragment.getMessage().contains("fragment"));
    }

    @Test
    void parseStripsBomAndRejectsEmptyFile() throws Exception {
        Path file = tempDir.resolve("bom.json");
        Files.write(file, ("\uFEFF" + validConfigJson(null)).getBytes(StandardCharsets.UTF_8));
        assertEquals("app_001", WopSdkConfigLoader.load(file).appKey());
        Path empty = tempDir.resolve("empty.json");
        Files.write(empty, "   ".getBytes(StandardCharsets.UTF_8));
        WopError error = assertThrows(WopError.class, () -> WopSdkConfigLoader.load(empty));
        assertTrue(error.getMessage().contains("空文件"));
    }

    @Test
    void nanInHttpClientFailsFast() {
        WopError error = assertThrows(WopError.class, () -> ConfigJsonParser.parse(
                "{\"appKey\":\"a\",\"suite\":\"WOP-RSA3072-SHA256\","
                        + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                        + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                        + "\"serverRoot\":\"https://gw.example.com/gateway\","
                        + "\"httpClient\":{\"connectTimeout\":NaN,\"readTimeout\":30000,\"maxRetryCount\":3}"
                        + "}"));
        assertTrue(error.getMessage().contains("JSON 解析失败")
                || error.getMessage().contains("NaN")
                || error.getMessage().contains("类型非法"));
    }

    @Test
    void joinUrlPreservesContextPath() {
        String url = ConfigUrlUtils.joinUrl("https://gw.example.com/gateway", "/gateway/order/create");
        assertEquals("https://gw.example.com/gateway/gateway/order/create", url);
    }

    @Test
    void wopSdkConfigToStringMasksKeys() throws Exception {
        WopSdkConfig cfg = WopSdkConfigLoader.load(writeConfig(validConfigJson(null)));
        String text = cfg.toString();
        assertTrue(text.contains("merchantPrivateKey=****"));
        assertTrue(!text.contains(RSA_PRIV));
    }
}
