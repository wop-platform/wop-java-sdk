package com.wopplatform.wopsdk.okhttp;

import com.wopplatform.wopsdk.RequestDraft;
import com.wopplatform.wopsdk.TransportResponse;
import com.wopplatform.wopsdk.WopSdkException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * OkHttp 适配器：MockWebServer 覆盖请求映射/响应映射/错误传播。
 */
class OkHttpTransportTest {

    private final MockWebServer server = new MockWebServer();

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    private void enqueue(int code, String body) {
        server.enqueue(new MockResponse().setResponseCode(code)
                .setHeader("X-Wop-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b")
                .setBody(body));
    }

    @Test
    void sendsDraftHeadersMethodAndBody() throws Exception {
        enqueue(200, "{\"ok\":true}");
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-wop-appkey", "app_001");
        headers.put("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/a/b");
        byte[] body = "{\"k\":1}".getBytes(StandardCharsets.UTF_8);
        TransportResponse response = transport.send(new RequestDraft("POST", "/gateway/x", headers, body));

        assertEquals(200, response.statusCode());
        assertEquals("{\"ok\":true}", new String(response.body(), StandardCharsets.UTF_8));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));

        var recorded = server.takeRequest();
        assertEquals("POST", recorded.getMethod());
        assertEquals("/gateway/x", recorded.getPath());
        assertEquals("app_001", recorded.getHeader("x-wop-appkey"));
        assertArrayEquals(body, recorded.getBody().readByteArray());
    }

    @Test
    void getWithoutBodySendsNoBody() throws Exception {
        enqueue(204, "");
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString().replaceAll("/$", ""));

        TransportResponse response = transport.send(
                new RequestDraft("GET", "/p", Map.of("x-wop-appkey", "a"), null));
        assertEquals(204, response.statusCode());
        assertEquals(0, response.body().length);

        var recorded = server.takeRequest();
        assertEquals("GET", recorded.getMethod());
        assertEquals(0, recorded.getBodySize());
    }

    @Test
    void absoluteUrlPathBypassesBaseUrl() throws Exception {
        enqueue(200, "abs");
        server.start();
        OkHttpTransport transport = new OkHttpTransport("http://invalid.example");
        TransportResponse response = transport.send(
                new RequestDraft("POST", server.url("/abs").toString(), Map.of(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals("/abs", server.takeRequest().getPath());
    }

    @Test
    void relativePathWithoutBaseUrlRejected() {
        OkHttpTransport transport = new OkHttpTransport((String) null);
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("baseUrl"));
    }

    @Test
    void ioFailureWrappedAsSdkException() throws Exception {
        server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
    }

    @Test
    void nullBodyResponseMappedToEmpty() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200));
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertNull(response.headers().get("x-wop-sign"));
        assertEquals(0, response.body().length);
    }

    @Test
    void defaultConstructorTrailingSlashBaseUrlAndRelativePath() throws Exception {
        enqueue(200, "x");
        server.start();
        // 尾斜杠 baseUrl + 无斜杠相对 path
        OkHttpTransport trailing = new OkHttpTransport(server.url("/sub/").toString());
        TransportResponse response = trailing.send(
                new RequestDraft("POST", "gateway/x", Map.of("x-wop-appkey", "a"), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals("/sub/gateway/x", server.takeRequest().getPath());

        // 无参构造（无 baseUrl）+ 相对 path → 明确拒绝
        OkHttpTransport noArg = new OkHttpTransport();
        assertThrows(WopSdkException.class, () -> noArg.send(
                new RequestDraft("POST", "/rel", Map.of(), new byte[]{1})));
    }

    @Test
    void headMethodSendsNoBody() throws Exception {
        enqueue(200, "");
        server.start();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("HEAD", "/p", Map.of("x-wop-appkey", "a"), null));
        assertEquals(200, response.statusCode());
        assertEquals("HEAD", server.takeRequest().getMethod());
    }

    @Test
    void blankBaseUrlTreatedAsAbsent() {
        OkHttpTransport blank = new OkHttpTransport("   ");
        assertThrows(WopSdkException.class, () -> blank.send(
                new RequestDraft("POST", "/rel", Map.of(), new byte[]{1})));
    }
}
