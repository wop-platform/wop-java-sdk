package com.wanlianyida.wop.jdkhttp;

import com.sun.net.httpserver.HttpServer;
import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
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
            byte[] body = readAll(exchange.getRequestBody());
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

    /** Java 8 无 InputStream.readAllBytes：手动循环读尽。 */
    private static byte[] readAll(java.io.InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int read;
        while ((read = in.read(chunk)) != -1) {
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    /** Java 8 无 Map.of：成对参数构造小请求头。 */
    private static Map<String, String> headers(String... kv) {
        Map<String, String> map = new LinkedHashMap<String, String>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return map;
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
                new RequestDraft("GET", "/gateway/x", headers("x-wop-appkey", "a"), null));
        assertEquals(200, response.statusCode());
        assertEquals("GET", seenMethod.get());
        assertEquals(0, seenBody.get().length);
    }

    @Test
    void absoluteUrlPathBypassesBaseUrl() throws Exception {
        String base = start("abs");
        JdkHttpTransport transport = new JdkHttpTransport("http://invalid.example");
        TransportResponse response = transport.send(
                new RequestDraft("POST", base + "/gateway/x", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
    }

    @Test
    void relativePathWithoutBaseUrlRejected() {
        JdkHttpTransport transport = new JdkHttpTransport();
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("baseUrl"));
    }

    @Test
    void patchMethodRejectedBeforeConnect() {
        // HttpURLConnection 仅接受标准方法：PATCH 等扩展方法开连接前显式拒绝（fail fast，
        // 不触网——baseUrl 指向必然拒收的端口，消息断言可区分"方法拒绝"与"连接失败"）。
        // 原 java.net.http 版可用 PATCH，此差异已在类 javadoc 声明；需 PATCH 请改用
        // okhttp/unirest 适配器。
        JdkHttpTransport transport = new JdkHttpTransport("http://127.0.0.1:1");
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("PATCH", "/p", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("PATCH"));
    }

    @Test
    void connectionFailureWrappedAsSdkException() {
        JdkHttpTransport transport = new JdkHttpTransport("http://127.0.0.1:1");
        assertThrows(WopSdkException.class,
                () -> transport.send(new RequestDraft("POST", "/p", headers(), new byte[]{1})));
    }

    @Test
    void interruptedThreadWrappedAsSdkException() throws Exception {
        String base = start("");
        JdkHttpTransport transport = new JdkHttpTransport(base);
        Thread.currentThread().interrupt();
        try {
            assertThrows(WopSdkException.class, () -> transport.send(
                    new RequestDraft("POST", "/gateway/x", headers(), new byte[]{1})));
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void headMethodAndTrailingSlashBaseUrl() throws Exception {
        String base = start("h");
        JdkHttpTransport trailing = new JdkHttpTransport(base + "/");
        TransportResponse response = trailing.send(
                new RequestDraft("HEAD", "gateway/x", headers("x-wop-appkey", "a"), null));
        assertEquals(200, response.statusCode());
        assertEquals("GET", seenMethod.get());

        JdkHttpTransport blank = new JdkHttpTransport("   ");
        assertThrows(WopSdkException.class, () -> blank.send(
                new RequestDraft("POST", "/rel", headers(), new byte[]{1})));
    }


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
                new RequestDraft("POST", "/big", headers(), new byte[]{1})));
        assertTrue(ex.getMessage().contains("上限"));
    }

    @Test
    void exactMaxBodyAccepted() throws Exception {
        String base = startFixedBody(JdkHttpTransport.MAX_RESPONSE_BYTES);
        JdkHttpTransport transport = new JdkHttpTransport(base);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/big", headers(), new byte[]{1}));
        assertEquals(200, response.statusCode());
        assertEquals(JdkHttpTransport.MAX_RESPONSE_BYTES, response.body().length);
        assertEquals((byte) 0x5A, response.body()[0]);
        assertEquals((byte) 0x5A, response.body()[JdkHttpTransport.MAX_RESPONSE_BYTES - 1]);
    }

    @Test
    void postWithoutWireBodySendsEmptyBody() throws Exception {
        String base = start("");
        JdkHttpTransport transport = new JdkHttpTransport(base);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/gateway/x", headers(), null));
        assertEquals(200, response.statusCode());
        assertEquals(0, seenBody.get().length);
    }


    @Test
    void sendWithNullCallUsesAdapterDefaults() throws Exception {
        String base = start("ok");
        JdkHttpTransport transport = new JdkHttpTransport(base);
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/gateway/x", headers("x-wop-appkey", "a"), new byte[]{1}), null);
        assertEquals(200, response.statusCode());
        assertEquals("POST", seenMethod.get());
    }

    @Test
    void callServerRootAndTimeoutsOverrideBaseUrl() throws Exception {
        String base = start("ok");
        JdkHttpTransport transport = new JdkHttpTransport();
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/gateway/x", headers("x-wop-appkey", "a"), new byte[]{1}),
                TransportCall.of(base, 1500, 2500));
        assertEquals(200, response.statusCode());
        assertEquals("POST", seenMethod.get());

        assertEquals(200, transport.send(
                new RequestDraft("POST", base + "/gateway/x", headers(), new byte[]{1}),
                TransportCall.of("", TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT)).statusCode());
    }

    @Test
    void supportsTransportCallAdvertised() {
        assertTrue(new JdkHttpTransport().supportsTransportCall());
    }
}
