package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopRequestContext;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.config.WopSdkConfigLoader;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PIT r2 补测：客户端装配与执行链（NullReturnVals / NegateConditionals / ConditionalsBoundary 变异）。
 * 每条用例都以「变异后行为必然不同」的可观察量为断言对象。
 */
class MutationKillClientTest {

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

    // ==================== 夹具 ====================

    private static Map<String, String> noHeaders() {
        return new LinkedHashMap<String, String>();
    }

    private static TransportResponse response(int status) {
        return new TransportResponse(status, noHeaders(), new byte[0]);
    }

    /** 记录草稿与调用参数、恒返回固定响应的传输桩。 */
    private static final class CapturingTransport implements Transport {

        private final TransportResponse response;
        private final AtomicReference<RequestDraft> draft = new AtomicReference<RequestDraft>();
        private final AtomicReference<TransportCall> call = new AtomicReference<TransportCall>();

        private CapturingTransport(TransportResponse response) {
            this.response = response;
        }

        @Override
        public TransportResponse send(RequestDraft draft) {
            return send(draft, TransportCall.empty());
        }

        @Override
        public TransportResponse send(RequestDraft draft, TransportCall call) {
            this.draft.set(draft);
            this.call.set(call);
            return response;
        }

        @Override
        public boolean supportsTransportCall() {
            return true;
        }
    }

    private static WopClient clientWith(Transport transport) {
        return WopClient.builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .expiredSeconds(1800L)
                .transport(transport)
                .build();
    }

    private static VerifyResult execute(WopClient client, WopRequestOptions options) {
        return client.execute("POST", "/gateway/x", "{}".getBytes(StandardCharsets.UTF_8),
                SecurityLevel.L0, options);
    }

    private static WopRequestContext failoverContext(List<String> candidates, int maxRetry) {
        WopSdkConfig.Builder builder = new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot(candidates.get(0))
                .expiredSeconds(1800L)
                .httpClient(new HttpClientSettings(10_000, 30_000, maxRetry));
        if (candidates.size() > 1) {
            builder.backupServerRoots(candidates.subList(1, candidates.size()).toArray(new String[0]));
        }
        return WopRequestContext.resolve(builder.build(), WopRequestOptions.none());
    }

    // ==================== defaultClient 缓存 ====================

    @Test
    void defaultClientReturnsNonNullCachedInstance() throws Exception {
        Path file = tempDir.resolve("wopSdkConfig.json");
        String json = "{"
                + "\"appKey\":\"app_cached\","
                + "\"suite\":\"WOP-RSA3072-SHA256\","
                + "\"merchantPrivateKey\":\"" + RSA_PRIV + "\","
                + "\"platformPublicKey\":\"" + RSA_PUB + "\","
                + "\"serverRoot\":\"https://gw.example.com/gateway\","
                + "\"expiredSeconds\":1800"
                + "}";
        Files.write(file, json.getBytes(StandardCharsets.UTF_8));
        System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, file.toString());
        WopSdkConfigLoader.clearCache();
        WopClient.resetDefault();

        WopClient first = WopClient.defaultClient();
        assertNotNull(first, "defaultClient 不得返回 null");
        // 第二次命中的是缓存快路径；变异为返回 null / 取反条件都会在此暴露
        assertSame(first, WopClient.defaultClient(), "第二次调用须复用同一实例");
    }

    // ==================== execute 覆盖与状态码 ====================

    @Test
    void executeAppliesRequestLevelAppKeyOverride() {
        CapturingTransport transport = new CapturingTransport(response(200));
        WopClient client = clientWith(transport);

        execute(client, WopRequestOptions.builder().appKey("app_override").build());

        assertNotNull(transport.draft.get(), "传输桩未收到草稿");
        assertEquals("app_override", transport.draft.get().headers().get("x-wop-appkey"));
    }

    @Test
    void executeAcceptsStatus200() {
        CapturingTransport transport = new CapturingTransport(response(200));
        WopClient client = clientWith(transport);
        assertDoesNotThrow(() -> execute(client, null));
    }

    @Test
    void executeRejectsStatus300() {
        CapturingTransport transport = new CapturingTransport(response(300));
        WopClient client = clientWith(transport);
        assertThrows(WopGatewayResponseException.class, () -> execute(client, null));
    }

    // ==================== Builder.httpClient ====================

    @Test
    void builderAppliesCustomHttpClientTimeouts() {
        CapturingTransport transport = new CapturingTransport(response(200));
        WopClient client = WopClient.builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .expiredSeconds(1800L)
                .httpClient(new HttpClientSettings(1234, 5678, 0))
                .transport(transport)
                .build();

        execute(client, null);

        assertNotNull(transport.call.get(), "传输桩未收到 TransportCall");
        assertEquals(1234, transport.call.get().connectTimeoutMillis());
        assertEquals(5678, transport.call.get().readTimeoutMillis());
    }

    // ==================== Failover 尝试次数上界 ====================

    @Test
    void failoverStopsAtMaxAttempts() {
        final AtomicInteger attempts = new AtomicInteger();
        Transport failing = new Transport() {
            @Override
            public TransportResponse send(RequestDraft draft) {
                return send(draft, TransportCall.empty());
            }

            @Override
            public TransportResponse send(RequestDraft draft, TransportCall call) {
                attempts.incrementAndGet();
                throw new WopSdkException("连接失败", new ConnectException("refused"));
            }

            @Override
            public boolean supportsTransportCall() {
                return true;
            }
        };
        List<String> candidates = Arrays.asList(
                "https://p1.example.com/gateway",
                "https://p2.example.com/gateway",
                "https://p3.example.com/gateway");
        FailoverTransport transport = new FailoverTransport(failing, failoverContext(candidates, 1));

        WopSdkException error = assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/gateway/x", noHeaders(), null)));

        assertEquals(2, attempts.get(), "3 候选 + maxRetryCount=1 ⇒ 至多 2 次尝试");
        assertTrue(error.getMessage().contains("已尝试 2 个"), error.getMessage());
    }
}
