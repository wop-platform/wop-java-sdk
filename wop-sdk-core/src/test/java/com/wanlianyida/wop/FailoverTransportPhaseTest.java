package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopRequestContext;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 传输阶段打标：连接阶段失败（含连接超时）可 failover；请求已发出后的失败一律不重试（K4）。
 * <p>
 * 打标必须按阶段而非异常类型判定——JDK/OkHttp 的连接超时与读超时同为
 * {@link SocketTimeoutException}，类型白名单无法区分。
 */
class FailoverTransportPhaseTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static WopRequestContext context(int maxRetry) {
        WopSdkConfig cfg = new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://a.example.com/gateway")
                .backupServerRoots("https://b.example.com/gateway")
                .expiredSeconds(1800L)
                .httpClient(new HttpClientSettings(10_000, 30_000, maxRetry))
                .build();
        return WopRequestContext.resolve(cfg, WopRequestOptions.none());
    }

    private static RequestDraft draft() {
        return new RequestDraft("POST", "/gateway/x", new LinkedHashMap<String, String>(), null);
    }

    @Test
    void connectPhaseSocketTimeoutFailsOver() {
        AtomicInteger attempts = new AtomicInteger();
        Transport delegate = new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft d) {
                return send(d, TransportCall.empty());
            }

            @Override
            public TransportResponse send(RequestDraft d, TransportCall call) {
                if (attempts.incrementAndGet() == 1) {
                    throw new WopSdkException("传输失败: Connect timed out",
                            new SocketTimeoutException("Connect timed out"),
                            WopSdkException.Phase.CONNECT);
                }
                return new TransportResponse(200, new LinkedHashMap<String, String>(), new byte[0]);
            }
        };
        WopRequestContext ctx = context(1);
        TransportResponse response = new FailoverTransport(delegate, ctx).send(draft(), ctx.toTransportCall());
        assertEquals(200, response.statusCode());
        assertEquals(2, attempts.get());
    }

    @Test
    void sentPhaseConnectExceptionIsNotRetried() {
        // 已发送后的失败即使底层是 ConnectException 也不重试：重发有重复副作用风险
        assertFalse(FailoverTransport.isPreSendRetryable(new WopSdkException(
                "传输失败", new ConnectException("Connection reset"), WopSdkException.Phase.SENT)));
    }

    @Test
    void connectPhaseIsRetryableRegardlessOfCause() {
        assertTrue(FailoverTransport.isPreSendRetryable(new WopSdkException(
                "传输失败", new IllegalStateException("handshake"), WopSdkException.Phase.CONNECT)));
        assertTrue(FailoverTransport.isPreSendRetryable(
                new WopSdkException("传输失败", null, WopSdkException.Phase.CONNECT)));
    }

    @Test
    void unknownPhaseFallsBackToCauseTypes() {
        // 未打标的 Transport（含第三方实现）：沿用类型白名单
        assertTrue(FailoverTransport.isPreSendRetryable(new WopSdkException(
                "传输失败", new ConnectException("Connection refused"))));
        assertFalse(FailoverTransport.isPreSendRetryable(new WopSdkException(
                "传输失败", new SocketTimeoutException("Connect timed out"))));
    }

    @Test
    void legacyConstructorsDefaultToUnknownPhase() {
        assertEquals(WopSdkException.Phase.UNKNOWN, new WopSdkException("配置错误").phase());
        assertEquals(WopSdkException.Phase.UNKNOWN,
                new WopSdkException("配置错误", new IllegalStateException("x")).phase());
        assertEquals(WopSdkException.Phase.UNKNOWN,
                new WopSdkException("配置错误", null, null).phase());
    }

    @Test
    void retryLimitReachedIsReportedDistinctlyFromAllCandidatesExhausted() {
        // 3 个候选但 maxRetry=0：只试 1 个就停，消息须说明是重试上限而非网关全不可用
        AtomicInteger attempts = new AtomicInteger();
        Transport delegate = new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft d) {
                attempts.incrementAndGet();
                throw new WopSdkException("传输失败: Connect timed out",
                        new SocketTimeoutException("Connect timed out"), WopSdkException.Phase.CONNECT);
            }

            @Override
            public TransportResponse send(RequestDraft d, TransportCall call) {
                return send(d);
            }
        };
        WopRequestContext ctx = WopRequestContext.resolve(new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://a.example.com/gateway")
                .backupServerRoots("https://b.example.com/gateway", "https://c.example.com/gateway")
                .expiredSeconds(1800L)
                .httpClient(new HttpClientSettings(10_000, 30_000, 0))
                .build(), WopRequestOptions.none());
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, ctx).send(draft(), ctx.toTransportCall()));
        assertTrue(ex.getMessage().contains("已达重试上限"), ex.getMessage());
        assertEquals(1, attempts.get());
    }

    @Test
    void exhaustedMessageSurvivesPhaseRetries() {
        Transport delegate = new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft d) {
                throw new WopSdkException("传输失败: Connect timed out",
                        new SocketTimeoutException("Connect timed out"), WopSdkException.Phase.CONNECT);
            }

            @Override
            public TransportResponse send(RequestDraft d, TransportCall call) {
                return send(d);
            }
        };
        WopRequestContext ctx = context(3);
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, ctx).send(draft(), ctx.toTransportCall()));
        assertTrue(ex.getMessage().contains("全部网关地址不可用（已尝试 2 个）"), ex.getMessage());
    }

    @Test
    void candidatesListStillGovernsBackupOrder() {
        // 打标不影响候选收敛：仅一个候选时首次失败即上抛
        AtomicInteger attempts = new AtomicInteger();
        Transport delegate = new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft d) {
                return send(d, TransportCall.empty());
            }

            @Override
            public TransportResponse send(RequestDraft d, TransportCall call) {
                attempts.incrementAndGet();
                throw new WopSdkException("传输失败: Connect timed out",
                        new SocketTimeoutException("Connect timed out"), WopSdkException.Phase.CONNECT);
            }
        };
        WopRequestContext single = WopRequestContext.resolve(new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://only.example.com/gateway")
                .expiredSeconds(1800L)
                .httpClient(new HttpClientSettings(10_000, 30_000, 3))
                .build(), WopRequestOptions.none());
        assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, single).send(draft(), single.toTransportCall()));
        assertEquals(1, attempts.get());
    }
}
