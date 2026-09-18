package com.wanlianyida.wop.config;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WopSdkConfig / HttpClientSettings / Builder 的值语义：
 * equals 九字段矩阵、transport 引用比较、打码输出、backups 防御拷贝、Builder null 安全。
 */
class ConfigValueSemanticsTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static final List<String> BACKUPS = Collections.singletonList("https://b.example.com/gateway");
    private static final HttpClientSettings HTTP = new HttpClientSettings(1000, 2000, 3);

    private static WopSdkConfig cfg(String appKey, String suite, String merchant, String platform,
                                    String serverRoot, List<String> backups, long expired,
                                    HttpClientSettings http, Transport transport) {
        return new WopSdkConfig(appKey, suite, merchant, platform, serverRoot, backups, expired, http, transport);
    }

    private static WopSdkConfig base(Transport transport) {
        return cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", BACKUPS, 1800L, HTTP, transport);
    }

    @Test
    void equalsReflexiveNullAndForeignType() {
        WopSdkConfig base = base(null);
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, "x");
    }

    @Test
    void equalsVaryEachField() {
        WopSdkConfig base = base(null);
        assertEquals(base, base(null));
        assertNotEquals(base, cfg("app_002", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", BACKUPS, 1800L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA4096-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", BACKUPS, 1800L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA3072-SHA256", "k1", RSA_PUB,
                "https://gw.example.com/gateway", BACKUPS, 1800L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, "k2",
                "https://gw.example.com/gateway", BACKUPS, 1800L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://other.example.com/gateway", BACKUPS, 1800L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway",
                Collections.singletonList("https://c.example.com/gateway"), 1800L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", BACKUPS, 60L, HTTP, null));
        assertNotEquals(base, cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", BACKUPS, 1800L,
                new HttpClientSettings(9, 2000, 3), null));
    }

    @Test
    void transportComparedByReference() {
        Transport a = draft -> null;
        Transport b = draft -> null;
        assertEquals(base(a), base(a));
        assertNotEquals(base(a), base(b));
        assertEquals(base(null), base(null));
        assertSame(a, base(a).transport());
    }

    @Test
    void hashCodeConsistentWithEquals() {
        WopSdkConfig x = base(null);
        WopSdkConfig y = base(null);
        assertEquals(x, y);
        assertEquals(x.hashCode(), y.hashCode());
        Map<WopSdkConfig, String> map = new HashMap<>();
        map.put(x, "v");
        assertEquals("v", map.get(y));
    }

    @Test
    void maskedStringHidesKeys() {
        WopSdkConfig base = base(null);
        String masked = base.toMaskedString();
        assertTrue(masked.contains("merchantPrivateKey=****"));
        assertTrue(masked.contains("platformPublicKey=****"));
        assertFalse(masked.contains(RSA_PRIV));
        assertFalse(masked.contains(RSA_PUB));
        assertEquals(masked, base.toString());
    }

    @Test
    void backupListDefensivelyCopiedAndUnmodifiable() {
        List<String> mutable = new ArrayList<>(Arrays.asList("https://b.example.com/gateway"));
        WopSdkConfig cfg = cfg("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB,
                "https://gw.example.com/gateway", mutable, 1800L, HTTP, null);
        mutable.add("https://mutated.example.com/gateway");
        assertEquals(1, cfg.backupServerRoots().size());
        assertThrows(UnsupportedOperationException.class,
                () -> cfg.backupServerRoots().add("https://x.example.com/gateway"));
    }

    @Test
    void builderNullVariantsSafe() {
        WopSdkConfig listNull = fullBuilder().backupServerRoots((List<String>) null).build();
        assertTrue(listNull.backupServerRoots().isEmpty());
        WopSdkConfig arrayNull = fullBuilder().backupServerRoots((String[]) null).build();
        assertTrue(arrayNull.backupServerRoots().isEmpty());
        WopSdkConfig httpNull = fullBuilder().httpClient(null).build();
        assertEquals(HttpClientSettings.defaults(), httpNull.httpClient());
    }

    @Test
    void emptyBuilderBuildRejectsMissingAppKey() {
        WopError e = assertThrows(WopError.class, () -> new WopSdkConfig.Builder().build());
        assertTrue(e.getMessage().contains("配置文件缺少必填项: appKey"), e.getMessage());
    }

    @Test
    void httpClientSettingsDefaultsAndEquality() {
        HttpClientSettings d = HttpClientSettings.defaults();
        assertEquals(10000, d.connectTimeout());
        assertEquals(30000, d.readTimeout());
        assertEquals(3, d.maxRetryCount());
        assertEquals(d, d);
        assertNotEquals(d, null);
        assertNotEquals(d, "x");
        assertNotEquals(d, new HttpClientSettings(1, 30000, 3));
        assertNotEquals(d, new HttpClientSettings(10000, 1, 3));
        assertNotEquals(d, new HttpClientSettings(10000, 30000, 1));
        assertEquals(d, new HttpClientSettings(10000, 30000, 3));
        assertEquals(d.hashCode(), new HttpClientSettings(10000, 30000, 3).hashCode());
        assertEquals("HttpClientSettings{connectTimeout=10000, readTimeout=30000, maxRetryCount=3}",
                d.toString());
    }

    private static WopSdkConfig.Builder fullBuilder() {
        return new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway");
    }
}
