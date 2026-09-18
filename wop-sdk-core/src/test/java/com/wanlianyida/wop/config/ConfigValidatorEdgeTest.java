package com.wanlianyida.wop.config;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ConfigValidator §3.4 语义校验消息、HTTP 参数校验与成功路径归一化全覆盖。
 */
class ConfigValidatorEdgeTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static WopSdkConfig raw(String appKey, String suite, String merchant, String platform,
                                    String serverRoot, java.util.List<String> backups, long expired,
                                    HttpClientSettings http) {
        return new WopSdkConfig(appKey, suite, merchant, platform, serverRoot, backups, expired, http, null);
    }

    private static WopSdkConfig valid() {
        return raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                HttpClientSettings.defaults());
    }

    private static void assertMissing(WopSdkConfig cfg, String field) {
        WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(cfg));
        assertTrue(e.getMessage().contains("配置文件缺少必填项: " + field), e.getMessage());
    }

    @Test
    void blankRequiredFieldsRejected() {
        for (String blank : new String[]{null, "", "   "}) {
            assertMissing(raw(blank, "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                    "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                    HttpClientSettings.defaults()), "appKey");
            assertMissing(raw("app_001", blank, RSA_PRIV, RSA_PUB,
                    "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                    HttpClientSettings.defaults()), "suite");
            assertMissing(raw("app_001", "WOP-RSA3072-SHA256", blank, RSA_PUB,
                    "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                    HttpClientSettings.defaults()), "merchantPrivateKey");
            assertMissing(raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, blank,
                    "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                    HttpClientSettings.defaults()), "platformPublicKey");
            assertMissing(raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                    blank, Collections.<String>emptyList(), 1800L,
                    HttpClientSettings.defaults()), "serverRoot");
        }
    }

    @Test
    void expiredSecondsMustBePositive() {
        for (long bad : new long[]{0L, -1L}) {
            WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(
                    raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                            "https://gw.example.com/gateway", Collections.<String>emptyList(), bad,
                            HttpClientSettings.defaults())));
            assertTrue(e.getMessage().contains("expiredSeconds 须为正整数"));
        }
    }

    @Test
    void unsupportedSuiteRejected() {
        WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(
                raw("app_001", "WOP-NOPE", RSA_PRIV, RSA_PUB,
                        "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                        HttpClientSettings.defaults())));
        assertTrue(e.getMessage().contains("不支持的算法套件: WOP-NOPE"));
    }

    @Test
    void malformedMerchantKeyRejected() {
        WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(
                raw("app_001", "WOP-RSA3072-SHA256", "not-a-key", RSA_PUB,
                        "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                        HttpClientSettings.defaults())));
        assertTrue(e.getMessage().contains("密钥解析失败"));
    }

    @Test
    void malformedPlatformKeyRejected() {
        WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(
                raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, "not-a-key",
                        "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                        HttpClientSettings.defaults())));
        assertTrue(e.getMessage().contains("密钥解析失败"));
    }

    @Test
    void nullHttpClientFallsBackToDefaults() {
        WopSdkConfig cfg = ConfigValidator.validateAndNormalize(raw("app_001", "WOP-RSA3072-SHA256",
                RSA_PRIV, RSA_PUB, "https://gw.example.com/gateway",
                Collections.<String>emptyList(), 1800L, null));
        assertEquals(HttpClientSettings.defaults(), cfg.httpClient());
    }

    @Test
    void httpClientTimeoutsValidated() {
        int[][] bad = {{0, 30000, 3}, {10000, 0, 3}, {10000, 30000, -1}};
        for (int[] b : bad) {
            WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(
                    raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                            "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                            new HttpClientSettings(b[0], b[1], b[2]))));
            assertTrue(e.getMessage().contains("超时须为正整数"), e.getMessage());
        }
    }

    @Test
    void invalidBackupUrlRejected() {
        WopError e = assertThrows(WopError.class, () -> ConfigValidator.validateAndNormalize(
                raw("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                        "https://gw.example.com/gateway", Arrays.asList("not a url"), 1800L,
                        HttpClientSettings.defaults())));
        assertTrue(e.getMessage().contains("backupServerRoots[0]"), e.getMessage());
        assertTrue(e.getMessage().contains("不是合法 URL"), e.getMessage());
    }

    @Test
    void successTrimsAndNormalizes() {
        WopSdkConfig cfg = ConfigValidator.validateAndNormalize(raw(
                "  app_001  ", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "HTTPS://GW.Example.COM/gateway/",
                Arrays.asList(" HTTPS://B.Example.COM:8443/GW "), 60L,
                HttpClientSettings.defaults()));
        assertEquals("app_001", cfg.appKey());
        assertEquals("WOP-RSA3072-SHA256", cfg.suite());
        assertEquals(RSA_PRIV, cfg.merchantPrivateKey());
        assertEquals(RSA_PUB, cfg.platformPublicKey());
        assertEquals("https://gw.example.com/gateway", cfg.serverRoot());
        assertEquals(Collections.singletonList("https://b.example.com:8443/GW"), cfg.backupServerRoots());
        assertEquals(60L, cfg.expiredSeconds());
    }

    @Test
    void transportReferencePreserved() {
        Transport probe = draft -> null;
        WopSdkConfig cfg = ConfigValidator.validateAndNormalize(new WopSdkConfig(
                "app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", Collections.<String>emptyList(), 1800L,
                HttpClientSettings.defaults(), probe));
        assertSame(probe, cfg.transport());
    }
}
