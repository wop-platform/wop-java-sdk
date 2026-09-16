package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopRequestContext;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P2：Failover 连接阶段重试与 K22 错误消息。 */
class FailoverTransportTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static WopRequestContext context(List<String> candidates, int maxRetry) {
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

    private static RequestDraft draft() {
        return new RequestDraft("POST", "/gateway/x", new LinkedHashMap<String, String>(), null);
    }

    @Test
    void retriesOnConnectFailureThenSucceeds() {
        AtomicInteger attempts = new AtomicInteger();
        Transport delegate = new Transport() {
            @Override
            public TransportResponse send(RequestDraft d) {
                return send(d, TransportCall.empty());
            }

            @Override
            public TransportResponse send(RequestDraft d, TransportCall call) {
                int n = attempts.incrementAndGet();
                if (n == 1) {
                    throw new WopSdkException("连接失败", new ConnectException("refused"));
                }
                assertEquals("https://backup.example.com/gateway", call.serverRoot());
                return new TransportResponse(200, Collections.emptyMap(), new byte[0]);
            }
        };
        WopRequestContext ctx = context(Arrays.asList(
                "https://primary.example.com/gateway",
                "https://backup.example.com/gateway"), 3);
        FailoverTransport failover = new FailoverTransport(delegate, ctx);
        TransportResponse resp = failover.send(draft(), ctx.toTransportCall());
        assertEquals(200, resp.statusCode());
        assertEquals(2, attempts.get());
    }

    @Test
    void readTimeoutIsNotRetried() {
        Transport delegate = new Transport() {
            @Override
            public TransportResponse send(RequestDraft d) {
                throw new WopSdkException("读超时", new SocketTimeoutException("read timed out"));
            }
        };
        WopRequestContext ctx = context(Arrays.asList(
                "https://a.example.com/gateway", "https://b.example.com/gateway"), 3);
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, ctx).send(draft(), ctx.toTransportCall()));
        assertTrue(ex.getMessage().contains("读超时"));
    }

    @Test
    void exhaustedAllCandidatesMessage() {
        Transport delegate = new Transport() {
            @Override
            public TransportResponse send(RequestDraft d) {
                throw new WopSdkException("连接失败", new ConnectException("refused"));
            }
        };
        WopRequestContext ctx = context(Arrays.asList(
                "https://a.example.com/gateway", "https://b.example.com/gateway"), 3);
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, ctx).send(draft(), ctx.toTransportCall()));
        assertTrue(ex.getMessage().contains("全部网关地址不可用（已尝试 2 个）"), ex.getMessage());
    }

    @Test
    void retryLimitMessageWhenCandidatesRemain() {
        Transport delegate = new Transport() {
            @Override
            public TransportResponse send(RequestDraft d) {
                throw new WopSdkException("连接失败", new ConnectException("refused"));
            }
        };
        WopRequestContext ctx = context(Arrays.asList(
                "https://a.example.com/gateway",
                "https://b.example.com/gateway",
                "https://c.example.com/gateway"), 1);
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, ctx).send(draft(), ctx.toTransportCall()));
        assertTrue(ex.getMessage().contains("已达重试上限 1"), ex.getMessage());
        assertTrue(ex.getMessage().contains("已尝试 2 个"), ex.getMessage());
    }

    @Test
    void isPreSendRetryableDetectsConnectException() {
        assertTrue(FailoverTransport.isPreSendRetryable(
                new WopSdkException("x", new ConnectException("refused"))));
    }
}
