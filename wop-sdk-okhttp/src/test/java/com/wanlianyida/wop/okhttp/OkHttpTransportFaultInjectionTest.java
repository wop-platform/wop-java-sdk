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

class OkHttpTransportFaultInjectionTest {

    /** Java 8 无 Map.of：成对参数构造小请求头。 */
    private static java.util.Map<String, String> headers(String... kv) {
        java.util.Map<String, String> map = new java.util.LinkedHashMap<String, String>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return map;
    }

    private final MockWebServer server = new MockWebServer();

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

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
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
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
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException);
    }

    @Test
    void midBodyDisconnectWrapped() throws Exception {
        server.enqueue(new MockResponse().setBody("partial").setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
    }

    @Test
    void tlsMismatchSurfacesAsSdkException() throws Exception {
        server.start();
        OkHttpClient noRetry = new OkHttpClient.Builder()
                .retryOnConnectionFailure(false)
                .connectTimeout(1, TimeUnit.SECONDS)
                .readTimeout(1, TimeUnit.SECONDS)
                .build();
        OkHttpTransport transport = new OkHttpTransport(
                server.url("/").toString().replace("http://", "https://"), noRetry);
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
    }

    @Test
    void serverErrorStatusPassedThroughUntouched() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(502).setBody("{\"code\":\"OP_GW_5001\"}"));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(502, response.statusCode());
        assertTrue(new String(response.body(), java.nio.charset.StandardCharsets.UTF_8)
                .contains("OP_GW_5001"));
    }

    @Test
    void unauthorizedErrorEnvelopeBodyReadable() throws Exception {
        // 跨适配器 401 回归哨兵（对齐 jdkhttp）：JDK HttpURLConnection 在 streaming 模式下
        // 遇 401/407 断连丢错误体是 JDK 专有缺陷；OkHttp 无此机制，错误信封体恒可读。
        // 同时验证附录 I 透传头随适配器原样上行。
        String envelope = "{\"code\":\"OP_GW_1001\",\"message\":\"appKey 为空或应用不存在\"}";
        server.enqueue(new MockResponse().setResponseCode(401).setBody(envelope));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(new RequestDraft("POST", "/p",
                headers("x-wop-request-id", "req-401"), new byte[]{1}));
        assertEquals(401, response.statusCode());
        assertEquals(envelope, new String(response.body(), java.nio.charset.StandardCharsets.UTF_8));
        assertEquals("req-401", server.takeRequest().getHeader("x-wop-request-id"));
    }

    @Test
    void responseHeaderNamesNormalizedToLowercase() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200)
                .addHeader("X-WOP-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b")
                .addHeader("X-Wop-Nonce", "N1"));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));
        assertEquals("N1", response.headers().get("x-wop-nonce"));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("X-WOP-SIGN"));
        assertTrue(response.headers().keySet().stream().allMatch(k -> k.equals(k.toLowerCase())));
    }
}
