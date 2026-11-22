package com.wanlianyida.wop.config;

import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.WopRequestOptions;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WopRequestContext resolve/resolveInboundOnly 合并语义：逐字段覆盖、退化 global 报错、
 * 候选去重、transport 级 options 剥离。
 */
class WopRequestContextEdgeTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String PRIMARY = "https://gw.example.com/gateway";
    private static final String BACKUP = "https://b.example.com/gateway";

    private static WopSdkConfig global(String appKey, String suite, String merchant, String platform,
                                       String serverRoot, List<String> backups, long expired,
                                       HttpClientSettings http) {
        return new WopSdkConfig(appKey, suite, merchant, platform, serverRoot, backups, expired, http, null);
    }

    private static WopSdkConfig validGlobal() {
        return global("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3));
    }

    private static void assertMissing(WopSdkConfig cfg, WopRequestOptions options, String field) {
        WopError e = assertThrows(WopError.class, () -> WopRequestContext.resolve(cfg, options));
        assertTrue(e.getMessage().contains("配置文件缺少必填项: " + field), e.getMessage());
    }

    @Test
    void resolveRequiresNonNullGlobal() {
        assertThrows(NullPointerException.class,
                () -> WopRequestContext.resolve(null, WopRequestOptions.none()));
    }

    @Test
    void nullAndEmptyOptionsResolveGlobalDefaults() {
        WopRequestContext ctx = WopRequestContext.resolve(validGlobal(), null);
        assertEquals("app_001", ctx.outbound().appKey());
        assertEquals("WOP-RSA3072-SHA256", ctx.outbound().suite().securityReq());
        assertEquals(1800L, ctx.outbound().expiredSeconds());
        assertNotNull(ctx.outbound().merchantPrivateKey());
        assertNotNull(ctx.outbound().platformPublicKey());
        assertEquals("WOP-RSA3072-SHA256", ctx.inbound().suite().securityReq());
        assertNotNull(ctx.inbound().merchantPrivateKey());
        assertNotNull(ctx.inbound().platformPublicKey());
        assertEquals(Arrays.asList(PRIMARY, BACKUP), ctx.failoverCandidates());
        assertEquals(PRIMARY, ctx.primaryServerRoot());
        assertEquals(3, ctx.maxRetryCount());
        assertEquals(TransportCall.of(PRIMARY, 10000, 30000), ctx.toTransportCall());
        assertEquals(TransportCall.of("https://alt.example.com/gateway", 10000, 30000),
                ctx.toTransportCall("https://alt.example.com/gateway"));
        // none() 等价于 null
        WopRequestContext viaNone = WopRequestContext.resolve(validGlobal(), WopRequestOptions.none());
        assertEquals(ctx.failoverCandidates(), viaNone.failoverCandidates());
        assertEquals(ctx.toTransportCall(), viaNone.toTransportCall());
    }

    @Test
    void optionOverridesMergedFieldByField() {
        assertEquals("app_002", WopRequestContext.resolve(validGlobal(),
                WopRequestOptions.builder().appKey("app_002").build()).outbound().appKey());
        assertEquals("WOP-RSA3072-SHA256", WopRequestContext.resolve(validGlobal(),
                WopRequestOptions.builder().suite("WOP-RSA3072-SHA256").build())
                .outbound().suite().securityReq());
        WopRequestContext keys = WopRequestContext.resolve(validGlobal(), WopRequestOptions.builder()
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build());
        assertNotNull(keys.outbound().merchantPrivateKey());
        assertNotNull(keys.inbound().platformPublicKey());
        assertEquals(60L, WopRequestContext.resolve(validGlobal(),
                WopRequestOptions.builder().expiredSeconds(60L).build()).outbound().expiredSeconds());
        WopRequestContext alt = WopRequestContext.resolve(validGlobal(), WopRequestOptions.builder()
                .serverRoot("https://alt.example.com/gateway").build());
        assertEquals("https://alt.example.com/gateway", alt.primaryServerRoot());
        assertEquals(Collections.singletonList("https://alt.example.com/gateway"), alt.failoverCandidates());
        assertEquals(TransportCall.of(PRIMARY, 2500, 3500), WopRequestContext.resolve(validGlobal(),
                WopRequestOptions.builder().connectTimeout(2500).readTimeout(3500).build())
                .toTransportCall());
    }

    @Test
    void degradedGlobalFailsPerFieldWhenOptionsDoNotRescue() {
        WopRequestOptions ctOnly = WopRequestOptions.builder().connectTimeout(2500).build();
        assertMissing(global("", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3)),
                ctOnly, "appKey");
        assertMissing(global("app_001", "", RSA_PRIV, RSA_PUB, PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3)),
                ctOnly, "suite");
        assertMissing(global("app_001", "WOP-RSA3072-SHA256", "", RSA_PUB, PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3)),
                ctOnly, "merchantPrivateKey");
        assertMissing(global("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, "", PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3)),
                ctOnly, "platformPublicKey");
        WopError expired = assertThrows(WopError.class, () -> WopRequestContext.resolve(
                global("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, PRIMARY,
                        Collections.singletonList(BACKUP), 0L, new HttpClientSettings(10000, 30000, 3)),
                ctOnly));
        assertTrue(expired.getMessage().contains("expiredSeconds 须为正整数"));
    }

    @Test
    void emptyGlobalServerRootFallsBackToBackupsWithoutThrowing() {
        // resolve 不校验 global serverRoot：主地址为空时候选仅剩 backups（行为断言）
        WopRequestContext ctx = WopRequestContext.resolve(
                global("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, "",
                        Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3)),
                WopRequestOptions.builder().connectTimeout(2500).build());
        assertEquals("", ctx.primaryServerRoot());
        assertEquals(Collections.singletonList(BACKUP), ctx.failoverCandidates());
    }

    @Test
    void invalidSuiteAndKeyOverridesRejected() {
        WopError suite = assertThrows(WopError.class, () -> WopRequestContext.resolve(validGlobal(),
                WopRequestOptions.builder().suite("WOP-NOPE").build()));
        assertTrue(suite.getMessage().contains("不支持的算法套件: WOP-NOPE"));
        WopError key = assertThrows(WopError.class, () -> WopRequestContext.resolve(validGlobal(),
                WopRequestOptions.builder().merchantPrivateKey("garbage").build()));
        assertTrue(key.getMessage().contains("密钥解析失败"));
    }

    @Test
    void globalTimeoutsValidatedWhenNotOverridden() {
        WopRequestOptions appKeyOnly = WopRequestOptions.builder().appKey("app_002").build();
        WopError e1 = assertThrows(WopError.class, () -> WopRequestContext.resolve(global(
                "app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(0, 30000, 3)), appKeyOnly));
        assertTrue(e1.getMessage().contains("超时须为正整数"), e1.getMessage());
        WopError e2 = assertThrows(WopError.class, () -> WopRequestContext.resolve(global(
                "app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, PRIMARY,
                Collections.singletonList(BACKUP), 1800L, new HttpClientSettings(10000, 0, 3)), appKeyOnly));
        assertTrue(e2.getMessage().contains("超时须为正整数"), e2.getMessage());
    }

    @Test
    void resolveInboundOnlyStripsTransportFields() {
        WopRequestOptions transportOnly = WopRequestOptions.builder()
                .serverRoot("https://alt.example.com/gateway")
                .connectTimeout(9999)
                .readTimeout(8888)
                .build();
        WopRequestContext ctx = WopRequestContext.resolveInboundOnly(validGlobal(), transportOnly);
        assertEquals(PRIMARY, ctx.primaryServerRoot());
        assertEquals(Arrays.asList(PRIMARY, BACKUP), ctx.failoverCandidates());
        assertEquals(TransportCall.of(PRIMARY, 10000, 30000), ctx.toTransportCall());
        assertEquals("app_001", ctx.outbound().appKey());
        // null options 走 none() 分支
        WopRequestContext nullCtx = WopRequestContext.resolveInboundOnly(validGlobal(), null);
        assertEquals(Arrays.asList(PRIMARY, BACKUP), nullCtx.failoverCandidates());
        // 显式 none() 与 null 同走空分支
        WopRequestContext noneCtx = WopRequestContext.resolveInboundOnly(validGlobal(), WopRequestOptions.none());
        assertEquals(Arrays.asList(PRIMARY, BACKUP), noneCtx.failoverCandidates());
    }

    @Test
    void failoverCandidatesSkipNullBlankAndDuplicates() {
        WopSdkConfig cfg = global("app_001", "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB, PRIMARY,
                Arrays.asList(null, "", PRIMARY, BACKUP), 1800L, new HttpClientSettings(10000, 30000, 3));
        assertEquals(Arrays.asList(PRIMARY, BACKUP),
                WopRequestContext.resolve(cfg, null).failoverCandidates());
    }

    @Test
    void maskedStringHidesKeys() {
        WopRequestContext ctx = WopRequestContext.resolve(validGlobal(), null);
        String masked = ctx.toMaskedString();
        assertTrue(masked.contains("merchantPrivateKey=****"));
        assertTrue(masked.contains("platformPublicKey=****"));
        assertFalse(masked.contains(RSA_PRIV));
        assertFalse(masked.contains(RSA_PUB));
        assertEquals(masked, ctx.toString());
    }
}
