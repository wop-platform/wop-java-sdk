package com.wanlianyida.wop.jdkhttp;

import com.sun.net.httpserver.HttpServer;
import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JDK HttpClient 适配器：com.sun.net.httpserver 覆盖请求/响应映射与错误传播。
 */
class JdkHttpTransportTest {

    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String start(String responseBody) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/gateway/x", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            seenBody.set(body);
            seenMethod.set(exchange.getRequestMethod());
            seenHeader.set(exchange.getRequestHeaders().getFirst("x-wop-appkey"));
            byte[] out = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Wop-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b");
            exchange.sendResponseHeaders(200, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private final AtomicReference<byte[]> seenBody = new AtomicReference<>();
    private final AtomicReference<String> seenMethod = new AtomicReference<>();
    private final AtomicReference<String> seenHeader = new AtomicReference<>();

    @Test
    void sendsDraftAndMapsResponse() throws Exception {
        String base = start("{\"ok\":true}");
        JdkHttpTransport transport = new JdkHttpTransport(base);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-wop-appkey", "app_001");
        byte[] body = "{\"k\":1}".getBytes(StandardCharsets.UTF_8);
        TransportResponse response = transport.send(new RequestDraft("POST", "/gateway/x", headers, body));

        assertEquals(200, response.statusCode());
        assertEquals("{\"ok\":true}", new String(response.body(), StandardCharsets.UTF_8));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));
        assertEquals("POST", seenMethod.get());
        assertEquals("app_001", seenHeader.get());
        assertArrayEquals(body, seenBody.get());
    }

    @Test
    void getWithoutBodySendsNoBody() throws Exception {
        String base = start("");
        JdkHttpTransport transport = new JdkHttpTransport(base);
        TransportResponse response = transport.send(
                new RequestDraft("GET", "/gateway/x", Map.of("x-wop-appkey", "a"), null));
        assertEquals(200, response.statusCode());
        assertEquals("GET", seenMethod.get());
        assertEquals(0, seenBody.get().length);
    }

    @Test
    void absoluteUrlPathBypassesBaseUrl() throws Exception {
        String base = start("abs");
        JdkHttpTransport transport = new JdkHttpTransport("http://invalid.example");
        TransportResponse response = transport.send(
                new RequestDraft("POST", base + "/gateway/x", Map.of(), new byte[]{1}));
        assertEquals(200, response.statusCode());
    }

    @Test
    void relativePathWithoutBaseUrlRejected() {
        JdkHttpTransport transport = new JdkHttpTransport();
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("baseUrl"));
    }

    @Test
    void connectionFailureWrappedAsSdkException() {
        // 无监听端口（保留 127.0.0.1 上一个几乎必然未占用的端口段）
        JdkHttpTransport transport = new JdkHttpTransport("http://127.0.0.1:1");
        assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", Map.of(), new byte[]{1})));
    }

    @Test
    void interruptedThreadWrappedAsSdkException() throws Exception {
        String base = start("");
        JdkHttpTransport transport = new JdkHttpTransport(base);
        Thread.currentThread().interrupt();
        try {
            assertThrows(WopSdkException.class, () -> transport.send(
                    new RequestDraft("POST", "/gateway/x", Map.of(), new byte[]{1})));
        } finally {
            Thread.interrupted();   // 消费 interrupt 标志，避免污染后续测试
        }
    }

    @Test
    void headMethodAndTrailingSlashBaseUrl() throws Exception {
        String base = start("h");
        JdkHttpTransport trailing = new JdkHttpTransport(base + "/");
        TransportResponse response = trailing.send(
                new RequestDraft("HEAD", "gateway/x", Map.of("x-wop-appkey", "a"), null));
        assertEquals(200, response.statusCode());
        assertEquals("GET", seenMethod.get());   // JDK HttpClient 将无 body 的 HEAD 归一为 GET

        JdkHttpTransport blank = new JdkHttpTransport("   ");
        assertThrows(WopSdkException.class, () -> blank.send(
                new RequestDraft("POST", "/rel", Map.of(), new byte[]{1})));
    }

    // spec:max-response-bytes —— 11MB 上限边界：超 1 字节拒 / 恰好上限过（流式计数，读取过程中生效）

    /** 启动返回固定长度 0x5A 填充体的服务器（大body场景，避免在内存里准备期望值）。 */
    private String startFixedBody(int length) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/big", exchange -> {
            exchange.sendResponseHeaders(200, length);
            try (OutputStream os = exchange.getResponseBody()) {
                byte[] chunk = new byte[64 * 1024];
                java.util.Arrays.fill(chunk, (byte) 0x5A);
                int remaining = length;
                while (remaining > 0) {
                    int n = Math.min(chunk.length, remaining);
                    os.write(chunk, 0, n);
                    remaining -= n;
                }
            } catch (IOException ignored) {
                // 客户端超限中止读取后断管属预期
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void oversizedBodyRejectedWhileStreaming() throws Exception {
        String base = startFixedBody(JdkHttpTransport.MAX_RESPONSE_BYTES + 1);
        JdkHttpTransport transport = new JdkHttpTransport(base);
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/big", Map.of(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"));
    }

    @Test
    void exactMaxBodyAccepted() throws Exception {
        String base = startFixedBody(JdkHttpTransport.MAX_RESPONSE_BYTES);
        JdkHttpTransport transport = new JdkHttpTransport(base);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/big", Map.of(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(JdkHttpTransport.MAX_RESPONSE_BYTES, response.body().length);
        assertEquals((byte) 0x5A, response.body()[0]);
        assertEquals((byte) 0x5A, response.body()[JdkHttpTransport.MAX_RESPONSE_BYTES - 1]);
    }
}
