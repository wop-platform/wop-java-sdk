package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.config.WopSdkConfigLoader;
import com.wanlianyida.wop.crypto.SignHeader;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** config-spec 补齐：K15/K26、C4 方向性凭证、§6.4 默认上下文缓存。 */
class WopClientConfigSpecTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String RSA4096_PRIV = TestVectors.keys("rsa4096").path("privatePkcs8B64").asText();
    private static final String RSA4096_PUB = TestVectors.keys("rsa4096").path("publicSpkiB64").asText();
    private static final String SM2_PRIV = TestVectors.keys("sm2").path("privateDB64").asText();
    private static final String SM2_PUB = TestVectors.keys("sm2").path("publicPointB64").asText();

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        clearConfigProperty();
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
                + "\"expiredSeconds\":1800,"
                + "\"httpClient\":{\"connectTimeout\":10000,\"readTimeout\":30000,\"maxRetryCount\":3}"
                + "}";
    }

    private Path writeConfig(String appKey) throws Exception {
        Path file = tempDir.resolve("wopSdkConfig.json");
        Files.write(file, validJson(appKey).getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static void clearConfigProperty() {
        System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
    }

    private static String appKeyFromDraft(RequestDraft draft) {
        return draft.headers().get("x-wop-appkey");
    }

    @Test
    void defaultClientConcurrentInitCreatesSingleInstance() throws Exception {
        Path file = writeConfig("app_concurrent");
        System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, file.toString());
        WopSdkConfigLoader.clearCache();
        WopClient.resetDefault();

        int threads = 8;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<WopClient>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    start.await(5, TimeUnit.SECONDS);
                    return WopClient.defaultClient();
                }));
            }
            ready.await(5, TimeUnit.SECONDS);
            start.countDown();
            WopClient first = futures.get(0).get(10, TimeUnit.SECONDS);
            for (Future<WopClient> future : futures) {
                assertSame(first, future.get(10, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void resetDefaultReloadsNewConfigConcurrently() throws Exception {
        Path file = writeConfig("app_v1");
        System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, file.toString());
        WopSdkConfigLoader.clearCache();
        WopClient.resetDefault();

        WopClient first = WopClient.defaultClient();
        assertEquals("app_v1", appKeyFromDraft(first.buildRequest(
                "POST", "/gateway/x", "{}".getBytes(StandardCharsets.UTF_8), SecurityLevel.L0)));

        WopSdkConfigLoader.clearCache();
        Files.write(file, validJson("app_v2").getBytes(StandardCharsets.UTF_8));
        WopClient.resetDefault();

        int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger v2Count = new AtomicInteger();
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    WopClient client = WopClient.defaultClient();
                    RequestDraft draft = client.buildRequest(
                            "POST", "/gateway/x", "{}".getBytes(StandardCharsets.UTF_8), SecurityLevel.L0);
                    if ("app_v2".equals(appKeyFromDraft(draft))) {
                        v2Count.incrementAndGet();
                    }
                }));
            }
            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(threads, v2Count.get());
        assertNotSame(first, WopClient.defaultClient());
    }

    @Test
    void outboundOptionsReflectInSignHeader() {
        WopSdkConfig config = new WopSdkConfig.Builder()
                .appKey("global_app")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .transport(draft -> new TransportResponse(200, Collections.emptyMap(), new byte[0]))
                .build();
        WopClient client = WopClient.fromConfig(config);
        WopRequestOptions options = WopRequestOptions.builder()
                .appKey("override_app")
                .expiredSeconds(900L)
                .build();
        RequestDraft draft = client.buildRequest(
                "POST", "/gateway/x", "{}".getBytes(StandardCharsets.UTF_8), SecurityLevel.L0, options);
        assertEquals("override_app", appKeyFromDraft(draft));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(900L, sign.expiredSeconds());
    }

    @Test
    void inboundPlatformKeyOverrideAffectsVerify() {
        WopClientVerifyTest.PlatformRig rig = new WopClientVerifyTest.PlatformRig(
                "WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        WopSdkConfig config = new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA4096-SHA256")
                .merchantPrivateKey(RSA4096_PRIV)
                .platformPublicKey(RSA4096_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .transport(draft -> new TransportResponse(200, Collections.emptyMap(), new byte[0]))
                .build();
        WopClient client = WopClient.fromConfig(config);
        byte[] plain = "{}".getBytes(StandardCharsets.UTF_8);
        WopClientVerifyTest.PlatformResponse resp = rig.respond("/gateway/x", plain, false);

        assertTrue(!client.verifyResponse(resp.headers(), resp.wire(), "/gateway/x").ok());

        VerifyResult ok = client.verifyResponse(
                resp.headers(), resp.wire(), "/gateway/x",
                WopRequestOptions.builder()
                        .suite("WOP-RSA3072-SHA256")
                        .platformPublicKey(RSA_PUB)
                        .merchantPrivateKey(RSA_PRIV)
                        .build());
        assertTrue(ok.ok(), () -> ok.toString());
    }

    @Test
    void sm2CallbackIgnoresOptionsAppKeyForZa() {
        WopClientVerifyTest.PlatformRig rig = new WopClientVerifyTest.PlatformRig(
                "WOP-SM2-SM3", SM2_PRIV, SM2_PUB);
        WopSdkConfig config = new WopSdkConfig.Builder()
                .appKey("app_sm2")
                .suite("WOP-SM2-SM3")
                .merchantPrivateKey(SM2_PRIV)
                .platformPublicKey(SM2_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .transport(draft -> new TransportResponse(200, Collections.emptyMap(), new byte[0]))
                .build();
        WopClient client = WopClient.fromConfig(config);
        byte[] plain = "{\"cb\":1}".getBytes(StandardCharsets.UTF_8);
        WopClientVerifyTest.PlatformResponse resp = rig.respond("/callback/x", plain, true);
        VerifyResult result = client.verifyCallback(
                resp.headers(), resp.wire(), "/callback/x",
                WopRequestOptions.builder().appKey("wrong_appkey_for_za").build());
        assertTrue(result.ok(), () -> result.toString());
    }

    @Test
    void requestOptionsToStringMasksKeys() {
        String text = WopRequestOptions.builder()
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .build()
                .toString();
        assertTrue(text.contains("merchantPrivateKey=****"));
        assertTrue(!text.contains(RSA_PRIV));
    }

    @Test
    void builderWithServerRootUsesFromConfigPath() {
        Transport transport = draft -> new TransportResponse(200, Collections.emptyMap(), new byte[0]);
        WopClient client = WopClient.builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .httpClient(HttpClientSettings.defaults())
                .transport(transport)
                .build();
        RequestDraft draft = client.buildRequest(
                "POST", "/gateway/x", "{}".getBytes(StandardCharsets.UTF_8), SecurityLevel.L0);
        assertEquals("app_001", appKeyFromDraft(draft));
    }
}
