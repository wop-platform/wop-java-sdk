package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.WopRequestOptions;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P1：resolve 复校验与 K3 Failover 关闭。 */
class WopRequestContextTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static WopSdkConfig baseConfig() {
        return new WopSdkConfig(
                "app_001",
                "WOP-RSA3072-SHA256",
                RSA_PRIV,
                RSA_PUB,
                "https://gw.example.com/gateway",
                Arrays.asList("https://gw-backup.example.com/gateway", "https://gw.example.com/gateway"),
                1800L,
                HttpClientSettings.defaults(),
                null);
    }

    @Test
    void resolveUsesGlobalFailoverCandidates() {
        WopRequestContext ctx = WopRequestContext.resolve(baseConfig(), WopRequestOptions.none());
        assertEquals(2, ctx.failoverCandidates().size());
        assertEquals("https://gw.example.com/gateway", ctx.failoverCandidates().get(0));
        assertEquals("https://gw-backup.example.com/gateway", ctx.failoverCandidates().get(1));
    }

    @Test
    void serverRootOverrideClosesFailover() {
        WopRequestOptions options = WopRequestOptions.builder()
                .serverRoot("https://alt.example.com/gateway")
                .build();
        WopRequestContext ctx = WopRequestContext.resolve(baseConfig(), options);
        assertEquals(Collections.singletonList("https://alt.example.com/gateway"), ctx.failoverCandidates());
    }

    @Test
    void resolveRevalidatesRequestLevelServerRoot() {
        WopRequestOptions options = WopRequestOptions.builder()
                .serverRoot("http://insecure.example.com/gateway")
                .build();
        WopError error = assertThrows(WopError.class, () -> WopRequestContext.resolve(baseConfig(), options));
        assertTrue(error.getMessage().contains("serverRoot"));
    }

    @Test
    void toStringMasksCredentialFields() {
        WopRequestContext ctx = WopRequestContext.resolve(baseConfig(), WopRequestOptions.none());
        String text = ctx.toString();
        assertTrue(text.contains("merchantPrivateKey=****"));
        assertTrue(!text.contains(RSA_PRIV));
    }

    @Test
    void resolveInboundOnlyIgnoresServerRoot() {
        WopRequestOptions options = WopRequestOptions.builder()
                .serverRoot("http://insecure.example.com/gateway")
                .platformPublicKey(RSA_PUB)
                .build();
        WopRequestContext ctx = WopRequestContext.resolveInboundOnly(baseConfig(), options);
        assertEquals(2, ctx.failoverCandidates().size());
    }
}
