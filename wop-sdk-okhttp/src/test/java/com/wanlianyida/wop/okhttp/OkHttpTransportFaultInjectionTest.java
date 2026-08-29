package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 故障注入（OkHttp 适配器网络层）：超时/断连/TLS 错配/5xx 透传/头名规范化。
 */
class OkHttpTransportFaultInjectionTest {

    private final MockWebServer server = new MockWebServer();

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    /** 不可路由地址 + 短连接超时 → 确定性 ConnectTimeout。 */
    private static OkHttpTransport unroutableClient() {
        OkHttpClient fast = new OkHttpClient.Builder()
                .connectTimeout(200, TimeUnit.MILLISECONDS)
                .readTimeout(200, TimeUnit.MILLISECONDS)
                .build();
        return new OkHttpTransport("http://10.255.255.1:81", fast);
    }

    @Test
    void connectTimeoutWrappedAsSdkException() {
        OkHttpTransport transport = unroutableClient();
        long start = System.nanoTime();
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("OkHttp"));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsedMs < 5_000, "超时应在秒级内返回，实际 " + elapsedMs + "ms");
    }

    @Test
    void readTimeoutOnDelayedResponseWrapped() throws Exception {
        server.enqueue(new MockResponse().setHeadersDelay(2, TimeUnit.SECONDS).setBody("late"));
        server.start();
        OkHttpClient fast = new OkHttpClient.Builder()
                .connectTimeout(1, TimeUnit.SECONDS)
                .readTimeout(200, TimeUnit.MILLISECONDS)
                .build();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString(), fast);
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException);
    }

    @Test
    void midBodyDisconnectWrapped() throws Exception {
        // 故障：响应体传输中断连
        server.enqueue(new MockResponse().setBody("partial").setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
    }

    @Test
    void tlsMismatchSurfacesAsSdkException() throws Exception {
        // 故障：https 指向明文端口（不 speak TLS 的对端）→ SSL/EOF 异常包装为明确异常；
        // 关闭静默重试确保快速失败
        server.start();
        OkHttpClient noRetry = new OkHttpClient.Builder()
                .retryOnConnectionFailure(false)
                .connectTimeout(1, TimeUnit.SECONDS)
                .readTimeout(1, TimeUnit.SECONDS)
                .build();
        OkHttpTransport transport = new OkHttpTransport(
                server.url("/").toString().replace("http://", "https://"), noRetry);
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
    }

    @Test
    void serverErrorStatusPassedThroughUntouched() throws Exception {
        // 故障：网关 502 —— 适配器只做透传，状态语义由 verify 层/商户决定
        server.enqueue(new MockResponse().setResponseCode(502).setBody("{\"code\":\"OP_GW_5001\"}"));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(502, response.statusCode());
        assertTrue(new String(response.body(), java.nio.charset.StandardCharsets.UTF_8)
                .contains("OP_GW_5001"));
    }

    @Test
    void responseHeaderNamesNormalizedToLowercase() throws Exception {
        // 契约：适配器送入 verify 层的头名恒小写存储；TransportResponse 为大小写不敏感视图
        server.enqueue(new MockResponse().setResponseCode(200)
                .addHeader("X-WOP-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b")
                .addHeader("X-Wop-Nonce", "N1"));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));
        assertEquals("N1", response.headers().get("x-wop-nonce"));
        // 大小写不敏感视图：任意形态查询命中同一值
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("X-WOP-SIGN"));
        assertTrue(response.headers().keySet().stream().allMatch(k -> k.equals(k.toLowerCase())));
    }
}
