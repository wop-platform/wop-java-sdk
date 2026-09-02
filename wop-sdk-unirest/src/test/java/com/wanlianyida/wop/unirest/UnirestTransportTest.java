package com.wanlianyida.wop.unirest;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unirest 适配器：MockWebServer 覆盖请求映射/响应映射/错误传播。
 */
class UnirestTransportTest {

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

    private void enqueue(int code, String body) {
        server.enqueue(new MockResponse().setResponseCode(code)
                .setHeader("X-Wop-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b")
                .setBody(body));
    }

    @Test
    void sendsDraftHeadersMethodAndBody() throws Exception {
        enqueue(200, "{\"ok\":true}");
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-wop-appkey", "app_001");
        headers.put("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/a/b");
        byte[] body = "{\"k\":1}".getBytes(StandardCharsets.UTF_8);
        TransportResponse response = transport.send(new RequestDraft("POST", "/gateway/x", headers, body));

        assertEquals(200, response.statusCode());
        assertEquals("{\"ok\":true}", new String(response.body(), StandardCharsets.UTF_8));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));

        RecordedRequest recorded = server.takeRequest();
        assertEquals("POST", recorded.getMethod());
        assertEquals("/gateway/x", recorded.getPath());
        assertEquals("app_001", recorded.getHeader("x-wop-appkey"));
        // draft 未带 content-type → 适配器补 application/octet-stream（与 OkHttp 适配器 body 媒体类型约定一致）
        assertEquals("application/octet-stream", recorded.getHeader("content-type"));
        // 未协商 gzip（requestCompression 已关），与 jdkhttp 适配器一致
        assertNull(recorded.getHeader("accept-encoding"));
        assertArrayEquals(body, recorded.getBody().readByteArray());
    }

    @Test
    void explicitDraftContentTypePreserved() throws Exception {
        enqueue(200, "ok");
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/json");
        transport.send(new RequestDraft("POST", "/p", headers, new byte[]{1}));

        assertEquals("application/json", server.takeRequest().getHeader("content-type"));
    }

    @Test
    void getWithoutBodySendsNoBody() throws Exception {
        enqueue(204, "");
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString().replaceAll("/$", ""));

        TransportResponse response = transport.send(
                new RequestDraft("GET", "/p", headers("x-wop-appkey", "a"), null));
        assertEquals(204, response.statusCode());
        assertEquals(0, response.body().length);

        RecordedRequest recorded = server.takeRequest();
        assertEquals("GET", recorded.getMethod());
        assertEquals(0, recorded.getBodySize());
    }

    @Test
    void headMethodWithWireSendsNoBody() throws Exception {
        enqueue(200, "");
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("HEAD", "/p", headers("x-wop-appkey", "a"), new byte[]{1, 2}));
        assertEquals(200, response.statusCode());
        RecordedRequest recorded = server.takeRequest();
        assertEquals("HEAD", recorded.getMethod());
        assertEquals(0, recorded.getBodySize());
    }

    @Test
    void absoluteUrlPathBypassesBaseUrl() throws Exception {
        enqueue(200, "abs");
        server.start();
        UnirestTransport transport = new UnirestTransport("http://invalid.example");
        TransportResponse response = transport.send(
                new RequestDraft("POST", server.url("/abs").toString(), headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals("/abs", server.takeRequest().getPath());
    }

    @Test
    void relativePathWithoutBaseUrlRejected() {
        UnirestTransport transport = new UnirestTransport((String) null);
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("baseUrl"));
    }

    @Test
    void ioFailureWrappedAsSdkException() throws Exception {
        // 本地保留端口抢占后立即释放 → 连接拒收（全本地确定性，不受系统代理影响）
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        UnirestTransport transport = new UnirestTransport("http://127.0.0.1:" + port);
        assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", headers(), new byte[]{1})));
    }

    @Test
    void nullBodyResponseMappedToEmpty() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertNull(response.headers().get("x-wop-sign"));
        assertEquals(0, response.body().length);
    }

    @Test
    void defaultConstructorTrailingSlashBaseUrlAndRelativePath() throws Exception {
        enqueue(200, "x");
        server.start();
        // 尾斜杠 baseUrl + 无斜杠相对 path
        UnirestTransport trailing = new UnirestTransport(server.url("/sub/").toString());
        TransportResponse response = trailing.send(
                new RequestDraft("POST", "gateway/x", headers("x-wop-appkey", "a"), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals("/sub/gateway/x", server.takeRequest().getPath());

        // 无参构造（无 baseUrl）+ 相对 path → 明确拒绝
        UnirestTransport noArg = new UnirestTransport();
        assertThrows(WopSdkException.class, () -> noArg.send(
                new RequestDraft("POST", "/rel", headers(), new byte[]{1})));
    }

    @Test
    void blankBaseUrlTreatedAsAbsent() {
        UnirestTransport blank = new UnirestTransport("   ");
        assertThrows(WopSdkException.class, () -> blank.send(
                new RequestDraft("POST", "/rel", headers(), new byte[]{1})));
    }

    // spec:max-response-bytes —— 11MB 上限边界：超 1 字节拒 / 恰好上限过（流式计数，读取过程中生效）

    @Test
    void oversizedBodyRejectedWhileStreaming() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200)
                .setBody(new okio.Buffer().write(new byte[UnirestTransport.MAX_RESPONSE_BYTES + 1])));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"));
    }

    @Test
    void exactMaxBodyAccepted() throws Exception {
        byte[] exact = new byte[UnirestTransport.MAX_RESPONSE_BYTES];
        new java.util.Random(42).nextBytes(exact);
        server.enqueue(new MockResponse().setResponseCode(200)
                .setBody(new okio.Buffer().write(exact)));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(UnirestTransport.MAX_RESPONSE_BYTES, response.body().length);
        assertArrayEquals(exact, response.body());
    }

    @Test
    void getWithWireSendsNoBody() throws Exception {
        enqueue(200, "x");
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("GET", "/p", headers("x-wop-appkey", "a"), new byte[]{9}));
        assertEquals(200, response.statusCode());
        RecordedRequest recorded = server.takeRequest();
        assertEquals("GET", recorded.getMethod());
        assertEquals(0, recorded.getBodySize());
    }

    @Test
    void chunkedResponseSkipsLengthCheck() throws Exception {
        // chunked 响应无 Content-Length 头 → 跳过截断校验，原样交付
        server.enqueue(new MockResponse().setResponseCode(200)
                .setChunkedBody(new okio.Buffer().writeUtf8("chunked-body"), 4));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals("chunked-body", new String(response.body(), StandardCharsets.UTF_8));
    }
}
