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
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 故障注入（Unirest 适配器网络层）：读超时/中途断流/5xx 透传/头名规范化/204 无实体。
 * 连接拒收场景见 {@link UnirestTransportTest}（本地保留端口，环境确定性更高）。
 */
class UnirestTransportFaultInjectionTest {

    private final MockWebServer server = new MockWebServer();

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    void readTimeoutWrappedAsSdkException() throws Exception {
        // 故障：服务器接受连接后不回任何字节 + 整体请求超时 500ms → 确定性超时
        server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString(),
                new UnirestInstance(new Config().connectTimeout(2_000).requestTimeout(500)));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("Unirest"));
    }

    @Test
    void midBodyDisconnectWrapped() throws Exception {
        // 故障：响应体传输中途断连 → 流读取 IOException 包装为明确异常
        server.enqueue(new MockResponse().setResponseCode(200)
                .setBody("0123456789")
                .setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
    }

    @Test
    void serverErrorStatusPassedThroughUntouched() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(500, response.statusCode());
        assertEquals("boom", new String(response.body(), StandardCharsets.UTF_8));
    }

    @Test
    void responseHeaderNamesNormalizedToLowercase() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200).setBody("x")
                .setHeader("X-Wop-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b"));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));
    }

    @Test
    void emptyBodyResponseMappedToEmptyArray() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(204));
        server.start();
        UnirestTransport transport = new UnirestTransport(server.url("/").toString());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(204, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void connectionResetDuringReadWrapped() throws Exception {
        // 故障：声明 Content-Length=1000 只写 10 字节即关闭 → 强制 RST，读流 IOException 包装为明确异常
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
                    new RequestDraft("POST", "/cut", Map.of(), new byte[]{1})));
        } finally {
            resetServer.stop(0);
        }
    }

    @Test
    void readErrorDuringStreamWrapped() throws Exception {
        // 故障：响应体传输中强制 RST（setSoLinger(0) 关闭即重置）→ 读流真实 IOException，覆盖 catch 分支
        try (java.net.ServerSocket listener = new java.net.ServerSocket(0, 1,
                java.net.InetAddress.getLoopbackAddress())) {
            Thread killer = new Thread(() -> {
                try (java.net.Socket socket = listener.accept()) {
                    java.io.InputStream in = socket.getInputStream();
                    int a = -1, b = -2, c = -3, d = -4;
                    while (!(a == '\r' && b == '\n' && c == '\r' && d == '\n')) {
                        a = b; b = c; c = d; d = in.read();
                        if (d < 0) return; // 客户端提前断开，放弃注入
                    }
                    in.read(); // 请求 body 1 字节，确保客户端发送完成
                    socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
                            .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
                    socket.getOutputStream().write(new byte[10]);
                    socket.getOutputStream().flush();
                    socket.setSoLinger(true, 0); // close → RST
                } catch (java.io.IOException ignored) {
                }
            });
            killer.start();
            UnirestTransport transport = new UnirestTransport(
                    "http://127.0.0.1:" + listener.getLocalPort());
            assertThrows(WopSdkException.class, () -> transport.send(
                    new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
            killer.join(5_000);
        }
    }

    @Test
    void readErrorFromInjectedStreamWrapped() {
        // 故障：注入 Client 产出读取即抛 IOException 的响应流 → 覆盖 readBodyLimited 读流异常路径
        InputStream body = new InputStream() {
            @Override public int read() throws IOException { throw new IOException("读流故障"); }
        };
        UnirestTransport transport = injectedTransport(body);
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("Unirest 传输失败"), ex.getMessage());
    }

    @Test
    void closeFailureAfterBodyIgnored() {
        // 故障：body 读完（EOF）后 close() 抛 IOException → 已读结果不受影响，覆盖关闭异常吞没路径
        InputStream body = new InputStream() {
            @Override public int read() { return -1; }
            @Override public void close() throws IOException { throw new IOException("close 故障"); }
        };
        UnirestTransport transport = injectedTransport(body);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void nullContentMappedToEmpty() {
        // 边界：getContent() 返回 null（无实体语义）→ 空 body 交付
        UnirestTransport transport = injectedTransport((InputStream) null);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void declaredLengthMismatchRejected() {
        // 截断校验：声明 Content-Length=100 实收 10 字节，读流正常 EOF（无读错误）→ 拒绝交付截断体
        Headers headers = new Headers();
        headers.add("Content-Length", "100");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[10]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("截断"), ex.getMessage());
    }

    @Test
    void headResponseWithNonZeroLengthNotTruncated() {
        // HEAD 无响应体（RFC 9110 §9.3.2），CL 描述 GET 表示长度 → 跳过截断校验
        Headers headers = new Headers();
        headers.add("Content-Length", "100");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[0]), headers));
        TransportResponse response = transport.send(new RequestDraft("HEAD", "/p", Map.of(), null));
        assertEquals(200, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void bodylessStatusesSkipLengthCheck() {
        // 1xx/204/205/304 无响应体（RFC 9110 §6.4），非零 CL 是表示描述 → 不判截断
        for (int status : new int[]{100, 204, 205, 304}) {
            Headers headers = new Headers();
            headers.add("Content-Length", "100");
            UnirestTransport transport = injectedTransport(rawResponseWithBody(
                    new ByteArrayInputStream(new byte[0]), headers, status));
            TransportResponse response = transport.send(
                    new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
            assertEquals(status, response.statusCode(), "status=" + status);
            assertEquals(0, response.body().length);
        }
    }

    @Test
    void malformedContentLengthRejectedAsSdkException() {
        // 畸形 CL 必须以 WopSdkException 落界（而非 NumberFormatException 泄漏）
        Headers headers = new Headers();
        headers.add("Content-Length", "12ab");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[2]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void negativeContentLengthRejected() {
        Headers headers = new Headers();
        headers.add("Content-Length", "-5");
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[0]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("畸形"), ex.getMessage());
    }

    @Test
    void declaredLengthOverLimitRejected() {
        // 声明超 11MiB 上限：显式拒绝（long 解析，int 范围外的合法值也不抛 NFE）
        Headers headers = new Headers();
        headers.add("Content-Length", String.valueOf((long) UnirestTransport.MAX_RESPONSE_BYTES + 1));
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[10]), headers));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"), ex.getMessage());
    }

    @Test
    void oversizedBodyWithoutDeclaredLengthRejected() {
        // chunked 语义（无 Content-Length）：实际读满上限+1 才置位 overflow → 读侧超限防线
        UnirestTransport transport = injectedTransport(rawResponseWithBody(
                new ByteArrayInputStream(new byte[UnirestTransport.MAX_RESPONSE_BYTES + 1]), new Headers()));
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("响应体超过"), ex.getMessage());
    }

    /** RawResponse 桩：getContent() 返回给定流（null 表示无实体），getHeaders() 返回给定头，其余为安全桩值。 */
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

    /** 以产出指定响应的伪 Client 构造 Transport（无网络，异常路径全确定性）。 */
    private static UnirestTransport injectedTransport(RawResponse response) {
        Client fakeClient = new Client() {
            @Override public <T> T getClient() { return null; }
            @Override public <T> HttpResponse<T> request(HttpRequest request,
                    Function<RawResponse, HttpResponse<T>> transformer, Class<?> resultType) {
                return transformer.apply(response);
            }
            @Override public <T> CompletableFuture<HttpResponse<T>> request(HttpRequest request,
                    Function<RawResponse, HttpResponse<T>> transformer,
                    CompletableFuture<HttpResponse<T>> callback, Class<?> resultType) {
                callback.complete(request(request, transformer, resultType));
                return callback;
            }
            @Override public WebSocketResponse websocket(WebSocketRequest request, WebSocket.Listener listener) {
                throw new UnsupportedOperationException();
            }
            @Override public CompletableFuture<Void> sse(SseRequest request, SseHandler handler) {
                throw new UnsupportedOperationException();
            }
            @Override public Stream<Event> sse(SseRequest request) {
                throw new UnsupportedOperationException();
            }
        };
        return new UnirestTransport("http://127.0.0.1:1/",
                new UnirestInstance(new Config().httpClient(fakeClient)));
    }

    private static UnirestTransport injectedTransport(InputStream body) {
        return injectedTransport(rawResponseWithBody(body));
    }
}
