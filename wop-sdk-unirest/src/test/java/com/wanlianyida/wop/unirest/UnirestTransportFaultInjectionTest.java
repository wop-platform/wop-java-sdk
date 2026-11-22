package com.wanlianyida.wop.unirest;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import kong.unirest.core.Client;
import kong.unirest.core.Config;
import kong.unirest.core.Headers;
import kong.unirest.core.HttpRequest;
import kong.unirest.core.HttpRequestSummary;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.HttpResponseSummary;
import kong.unirest.core.RawResponse;
import kong.unirest.core.SseHandler;
import kong.unirest.core.SseRequest;
import kong.unirest.core.UnirestInstance;
import kong.unirest.core.WebSocketRequest;
import kong.unirest.core.WebSocketResponse;
import kong.unirest.core.java.Event;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnirestTransportFaultInjectionTest {

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

    @Test
    void readTimeoutWrappedAsSdkException() throws Exception {
        server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString(),
                new UnirestInstance(new Config().connectTimeout(2_000).requestTimeout(500)));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("Unirest"));
    }

    @Test
    void midBodyDisconnectWrapped() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200)
                .setBody("0123456789")
                .setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
    }

    @Test
    void serverErrorStatusPassedThroughUntouched() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(500, response.statusCode());
        assertEquals("boom", new String(response.body(), StandardCharsets.UTF_8));
    }

    @Test
    void unauthorizedErrorEnvelopeBodyReadable() throws Exception {
        // 跨适配器 401 回归哨兵（对齐 jdkhttp）：JDK HttpURLConnection 在 streaming 模式下
        // 遇 401/407 断连丢错误体是 JDK 专有缺陷；Unirest RawResponse 无此机制，信封体恒可读。
        // 同时验证附录 I 透传头随适配器原样上行。
        String envelope = "{\"code\":\"OP_GW_1001\",\"message\":\"appKey 为空或应用不存在\"}";
        server.enqueue(new MockResponse().setResponseCode(401).setBody(envelope));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(new RequestDraft("POST", "/p",
                headers("x-wop-request-id", "req-401"), new byte[]{1}));
        assertEquals(401, response.statusCode());
        assertEquals(envelope, new String(response.body(), StandardCharsets.UTF_8));
        assertEquals("req-401", server.takeRequest().getHeader("x-wop-request-id"));
    }

    @Test
    void responseHeaderNamesNormalizedToLowercase() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200).setBody("x")
                .setHeader("X-Wop-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b"));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));
    }

    @Test
    void emptyBodyResponseMappedToEmptyArray() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(204));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(204, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void connectionResetDuringReadWrapped() throws Exception {
        com.sun.net.httpserver.HttpServer resetServer = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        resetServer.createContext("/cut", exchange -> {
            exchange.getResponseHeaders().add("Content-Length", "1000");
            exchange.sendResponseHeaders(200, 1000);
            try (java.io.OutputStream os = exchange.getResponseBody()) {
                os.write(new byte[10]);
            }
        });
        resetServer.start();
        try {
            UnirestTransport transport = new UnirestTransport(
                    "http://127.0.0.1:" + resetServer.getAddress().getPort());
            assertThrows(WopSdkException.class, () -> transport.send(
                    new RequestDraft("POST", "/cut", headers(), new byte[]{1})));
        } finally {
            resetServer.stop(0);
        }
    }

    @Test
    void readErrorDuringStreamWrapped() throws Exception {
        try (java.net.ServerSocket listener = new java.net.ServerSocket(0, 1,
                java.net.InetAddress.getLoopbackAddress())) {
            Thread killer = new Thread(() -> {
                try (java.net.Socket socket = listener.accept()) {
                    java.io.InputStream in = socket.getInputStream();
                    int a = -1, b = -2, c = -3, d = -4;
                    while (!(a == '\r' && b == '\n' && c == '\r' && d == '\n')) {
                        a = b; b = c; c = d; d = in.read();
                        if (d < 0) return;
                    }
                    in.read();
                    socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
                            .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
                    socket.getOutputStream().write(new byte[10]);
                    socket.getOutputStream().flush();
                    socket.setSoLinger(true, 0);
                } catch (java.io.IOException ignored) {
                }
            });
            killer.start();
            UnirestTransport transport = new UnirestTransport(
                    "http://127.0.0.1:" + listener.getLocalPort());
            assertThrows(WopSdkException.class, () -> transport.send(
                    new RequestDraft("POST", "/p", headers(), new byte[]{1})));
            killer.join(5_000);
        }
    }

    @Test
    void readErrorFromInjectedStreamWrapped() {
        InputStream body = new InputStream() {
            @Override public int read() throws IOException { throw new IOException("读流故障"); }
        };
        UnirestTransport transport = injectedTransport(body);
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("Unirest 传输失败"), ex.getMessage());
    }

    @Test
    void closeFailureAfterBodyIgnored() {
        InputStream body = new InputStream() {
            @Override public int read() { return -1; }
            @Override public void close() throws IOException { throw new IOException("close 故障"); }
        };
        UnirestTransport transport = injectedTransport(body);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void nullContentMappedToEmpty() {
        UnirestTransport transport = injectedTransport((InputStream) null);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void declaredLengthMismatchRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", "100");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[10]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("截断"), ex.getMessage());
    }

    @Test
    void headResponseWithNonZeroLengthNotTruncated() {
        Headers headers = new Headers();
        headers.add("Content-Length", "100");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[0]), headers));
        TransportResponse response = transport.send(new RequestDraft("HEAD", "/p", headers(), null));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void headWithOversizedDeclaredLengthNotRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", String.valueOf((long) UnirestTransport.MAX_RESPONSE_BYTES * 2));
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[0]), headers));
        TransportResponse response = transport.send(new RequestDraft("HEAD", "/big", headers(), null));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void bodylessStatusesSkipLengthCheck() {
        for (int status : new int[]{100, 204, 205, 304}) {
            Headers headers = new Headers();
            headers.add("Content-Length", "100");
            UnirestTransport transport = injectedTransport(rawResponseWithBody(
                    new ByteArrayInputStream(new byte[0]), headers, status));
            TransportResponse response = transport.send(
                    new RequestDraft("POST", "/p", headers(), new byte[]{1}));
            assertEquals(status, response.statusCode(), "status=" + status);
            assertEquals(0, response.body().length);
        }
    }

    @Test
    void malformedContentLengthRejectedAsSdkException() {
        Headers headers = new Headers();
        headers.add("Content-Length", "12ab");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[2]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void negativeContentLengthRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", "-5");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[0]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void declaredLengthOverLimitRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", String.valueOf((long) UnirestTransport.MAX_RESPONSE_BYTES + 1));
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[10]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"), ex.getMessage());
    }

    @Test
    void oversizedBodyWithoutDeclaredLengthRejected() {
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[UnirestTransport.MAX_RESPONSE_BYTES + 1]), new Headers()));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("响应体超过"), ex.getMessage());
    }

    @Test
    void duplicateContentLengthConsistentAccepted() {
        Headers headers = new Headers();
        headers.add("Content-Length", "100");
        headers.add("Content-Length", "0100");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[100]), headers));
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(100, response.body().length);
    }

    @Test
    void duplicateContentLengthInconsistentRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", "100");
        headers.add("Content-Length", "0");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[10]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("不一致"), ex.getMessage());
    }

    @Test
    void signedContentLengthRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", "+5");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[5]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void oversizedNumericContentLengthRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", "99999999999999999999");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[5]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void blankContentLengthRejected() {
        // 空白值 CL：trim 后为空串，属畸形而非"无声明"（后者会被走私利用）
        Headers headers = new Headers();
        headers.add("Content-Length", "  ");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[5]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void precheckRejectsBeforeReadingBody() {
        Headers headers = new Headers();
        headers.add("Content-Length", String.valueOf((long) UnirestTransport.MAX_RESPONSE_BYTES + 1));
        AtomicInteger reads = new AtomicInteger();
        InputStream counting = new InputStream() {
            @Override public int read() { reads.incrementAndGet(); return -1; }
            @Override public int read(byte[] b, int off, int len) { reads.incrementAndGet(); return -1; }
        };
        UnirestTransport transport = injectedTransport(rawResponseWithBody(counting, headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"), ex.getMessage());
        assertEquals(0, reads.get(), "先验拒绝不应读取响应体");
    }

    @Test
    void oversizedDeclaredWithFailingCloseStillRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", String.valueOf((long) UnirestTransport.MAX_RESPONSE_BYTES + 1));
        InputStream failingClose = new ByteArrayInputStream(new byte[0]) {
            @Override public void close() { throw new RuntimeException("close boom"); }
        };
        UnirestTransport transport = injectedTransport(rawResponseWithBody(failingClose, headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"), ex.getMessage());
    }

    @Test
    void malformedClWithNullContentStillRejected() {
        // 无实体（getContent()=null）+ 畸形声明：跳过关流分支，畸形错误仍落界
        Headers headers = new Headers();
        headers.add("Content-Length", "12ab");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(null, headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    private static RawResponse rawResponseWithBody(InputStream body) {
        return rawResponseWithBody(body, new Headers(), 200);
    }
    private static RawResponse rawResponseWithBody(InputStream body, Headers headers) {
        return rawResponseWithBody(body, headers, 200);
    }
    private static RawResponse rawResponseWithBody(InputStream body, Headers headers, int status) {
        return rawResponseWithBody(body, headers, status, "OK");
    }

    private static RawResponse rawResponseWithBody(InputStream body, Headers headers, int status, String statusText) {
        return new RawResponse() {
            @Override public int getStatus() { return status; }
            @Override public String getStatusText() { return statusText; }
            @Override public Headers getHeaders() { return headers; }
            @Override public InputStream getContent() { return body; }
            @Override public byte[] getContentAsBytes() { return new byte[0]; }
            @Override public String getContentAsString() { return ""; }
            @Override public String getContentAsString(String charset) { return ""; }
            @Override public InputStreamReader getContentReader() { throw new UnsupportedOperationException(); }
            @Override public boolean hasContent() { return body != null; }
            @Override public String getContentType() { return "application/octet-stream"; }
            @Override public String getEncoding() { return null; }
            @Override public Config getConfig() { return null; }
            @Override public HttpRequestSummary getRequestSummary() { return null; }
            @Override public HttpResponseSummary toSummary() { return null; }
        };
    }

    @SuppressWarnings("unchecked")
    private static UnirestTransport injectedTransport(RawResponse response) {
        Client fakeClient = (Client) java.lang.reflect.Proxy.newProxyInstance(
                Client.class.getClassLoader(), new Class<?>[]{Client.class},
                (proxy, method, args) -> {
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    if ("equals".equals(method.getName())) {
                        return proxy == args[0];
                    }
                    if ("toString".equals(method.getName())) {
                        return "fakeClient";
                    }
                    if ("getClient".equals(method.getName())) {
                        return null;
                    }
                    if ("request".equals(method.getName()) && method.getParameterCount() == 3) {
                        Function<RawResponse, HttpResponse<Object>> transformer =
                                (Function<RawResponse, HttpResponse<Object>>) args[1];
                        return transformer.apply(response);
                    }
                    if ("request".equals(method.getName()) && method.getParameterCount() == 4) {
                        Function<RawResponse, HttpResponse<Object>> transformer =
                                (Function<RawResponse, HttpResponse<Object>>) args[1];
                        CompletableFuture<HttpResponse<Object>> callback =
                                (CompletableFuture<HttpResponse<Object>>) args[2];
                        callback.complete(transformer.apply(response));
                        return callback;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return new UnirestTransport("http://127.0.0.1:1/",
                new UnirestInstance(new Config().httpClient(fakeClient)));
    }

    private static UnirestTransport injectedTransport(InputStream body) {
        return injectedTransport(rawResponseWithBody(body));
    }
}
