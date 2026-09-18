package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WopRequestOptions 值语义：none 单例、has* 判定矩阵、isEmpty、
 * equals 八字段、toString 打码与 Builder 负数守卫（§6.1）。
 */
class WopRequestOptionsTest {

    @Test
    void noneIsSingletonAndEmpty() {
        assertSame(WopRequestOptions.none(), WopRequestOptions.none());
        WopRequestOptions none = WopRequestOptions.none();
        assertTrue(none.isEmpty());
        assertNull(none.appKey());
        assertNull(none.suite());
        assertNull(none.merchantPrivateKey());
        assertNull(none.platformPublicKey());
        assertEquals(0L, none.expiredSeconds());
        assertNull(none.serverRoot());
        assertEquals(0, none.connectTimeout());
        assertEquals(0, none.readTimeout());
    }

    @Test
    void stringHasPredicates() {
        for (String blank : new String[]{null, "", "   "}) {
            assertFalse(WopRequestOptions.builder().appKey(blank).build().hasAppKey());
            assertFalse(WopRequestOptions.builder().suite(blank).build().hasSuite());
            assertFalse(WopRequestOptions.builder().merchantPrivateKey(blank).build().hasMerchantPrivateKey());
            assertFalse(WopRequestOptions.builder().platformPublicKey(blank).build().hasPlatformPublicKey());
            assertFalse(WopRequestOptions.builder().serverRoot(blank).build().hasServerRoot());
        }
        assertTrue(WopRequestOptions.builder().appKey("a").build().hasAppKey());
        assertTrue(WopRequestOptions.builder().suite("s").build().hasSuite());
        assertTrue(WopRequestOptions.builder().merchantPrivateKey("m").build().hasMerchantPrivateKey());
        assertTrue(WopRequestOptions.builder().platformPublicKey("p").build().hasPlatformPublicKey());
        assertTrue(WopRequestOptions.builder().serverRoot("https://x.example.com/gateway").build().hasServerRoot());
    }

    @Test
    void numericHasPredicates() {
        assertFalse(WopRequestOptions.builder().expiredSeconds(0L).build().hasExpiredSeconds());
        assertTrue(WopRequestOptions.builder().expiredSeconds(60L).build().hasExpiredSeconds());
        assertFalse(WopRequestOptions.builder().connectTimeout(0).build().hasConnectTimeout());
        assertTrue(WopRequestOptions.builder().connectTimeout(2500).build().hasConnectTimeout());
        assertFalse(WopRequestOptions.builder().readTimeout(0).build().hasReadTimeout());
        assertTrue(WopRequestOptions.builder().readTimeout(3500).build().hasReadTimeout());
    }

    @Test
    void isEmptyFalseWhenAnyFieldSet() {
        assertFalse(WopRequestOptions.builder().appKey("a").build().isEmpty());
        assertFalse(WopRequestOptions.builder().suite("s").build().isEmpty());
        assertFalse(WopRequestOptions.builder().merchantPrivateKey("m").build().isEmpty());
        assertFalse(WopRequestOptions.builder().platformPublicKey("p").build().isEmpty());
        assertFalse(WopRequestOptions.builder().expiredSeconds(60L).build().isEmpty());
        assertFalse(WopRequestOptions.builder().serverRoot("https://x.example.com/gateway").build().isEmpty());
        assertFalse(WopRequestOptions.builder().connectTimeout(1).build().isEmpty());
        assertFalse(WopRequestOptions.builder().readTimeout(1).build().isEmpty());
    }

    @Test
    void equalsAndHashCodeVaryEachField() {
        WopRequestOptions base = full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500);
        assertEquals(base, base);
        assertEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500));
        assertEquals(base.hashCode(), full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500).hashCode());
        assertNotEquals(base, null);
        assertNotEquals(base, "x");
        assertNotEquals(base, full("z", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500));
        assertNotEquals(base, full("a", "z", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500));
        assertNotEquals(base, full("a", "s", "z", "p", 60L, "https://x.example.com/gateway", 2500, 3500));
        assertNotEquals(base, full("a", "s", "m", "z", 60L, "https://x.example.com/gateway", 2500, 3500));
        assertNotEquals(base, full("a", "s", "m", "p", 61L, "https://x.example.com/gateway", 2500, 3500));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://z.example.com/gateway", 2500, 3500));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 1, 3500));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 1));
    }

    @Test
    void emptyBuildEqualsNone() {
        assertEquals(WopRequestOptions.none(), WopRequestOptions.builder().build());
        assertEquals(WopRequestOptions.builder().build(), WopRequestOptions.none());
    }

    @Test
    void toStringMasksCredentials() {
        String s = WopRequestOptions.builder()
                .appKey("a").suite("s").merchantPrivateKey("secret-m").platformPublicKey("secret-p")
                .build().toString();
        assertTrue(s.contains("merchantPrivateKey=****"));
        assertTrue(s.contains("platformPublicKey=****"));
        assertFalse(s.contains("secret-m"));
        assertFalse(s.contains("secret-p"));
    }

    @Test
    void builderRejectsNegatives() {
        WopError e1 = assertThrows(WopError.class, () -> WopRequestOptions.builder().expiredSeconds(-1L));
        assertTrue(e1.getMessage().contains("expiredSeconds 不能为负数"));
        WopError e2 = assertThrows(WopError.class, () -> WopRequestOptions.builder().connectTimeout(-1));
        assertTrue(e2.getMessage().contains("connectTimeout 不能为负数"));
        WopError e3 = assertThrows(WopError.class, () -> WopRequestOptions.builder().readTimeout(-1));
        assertTrue(e3.getMessage().contains("readTimeout 不能为负数"));
    }

    private static WopRequestOptions full(String appKey, String suite, String merchant, String platform,
                                          long expired, String serverRoot, int connectTimeout, int readTimeout) {
        return WopRequestOptions.builder()
                .appKey(appKey).suite(suite).merchantPrivateKey(merchant).platformPublicKey(platform)
                .expiredSeconds(expired).serverRoot(serverRoot)
                .connectTimeout(connectTimeout).readTimeout(readTimeout).build();
    }
}
