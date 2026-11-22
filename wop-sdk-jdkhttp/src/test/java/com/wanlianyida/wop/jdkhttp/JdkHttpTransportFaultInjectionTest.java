package com.wanlianyida.wop.jdkhttp;

import com.sun.net.httpserver.HttpServer;
import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdkHttpTransportFaultInjectionTest {

    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Java 8 无 Map.of：成对参数构造小请求头。 */
    private static Map<String, String> headers(String... kv) {
        Map<String, String> map = new java.util.LinkedHashMap<String, String>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return map;
    }

    @Test
    void connectionResetDuringBodyWrapped() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/cut", exchange -> {
            exchange.getResponseHeaders().add("Content-Length", "1000");
            exchange.sendResponseHeaders(200, 1000);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(new byte[10]);
            }
        });
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        assertThrows(WopSdkException.class, () -> transport.send(
                new RequestDraft("POST", "/cut", headers(), new byte[]{1})));
    }

    @Test
    void serverErrorStatusPassedThroughUntouched() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> {
            byte[] out = "{\"code\":\"OP_GW_5001\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(502, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(502, response.statusCode());
        assertTrue(new String(response.body(), java.nio.charset.StandardCharsets.UTF_8)
                .contains("OP_GW_5001"));
    }

    @Test
    void responseHeaderNamesNormalizedToLowercase() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> {
            exchange.getResponseHeaders().add("X-Wop-Sign", "WOP-RSA3072-SHA256 v1/1800/a/b");
            exchange.sendResponseHeaders(200, -1);
        });
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("x-wop-sign"));
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("X-WOP-SIGN"));
        assertTrue(response.headers().keySet().stream().allMatch(k -> k.equals(k.toLowerCase())));
    }

    @Test
    void emptyBodyResponseMappedToEmptyArray() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> exchange.sendResponseHeaders(204, -1));
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(204, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void errorStatusWithoutBodyMappedToEmptyArray() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> exchange.sendResponseHeaders(404, -1));
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(404, response.statusCode());
        assertEquals(0, response.body().length);
    }

    @Test
    void bodylessStatusesSkipLengthCheck() throws Exception {
        // 契约：204/304 禁止实体，空 body 是合法终态而非截断（部分网关在无实体响应上
        // 仍带 stale Content-Length，不做长度比对）。两个状态分别命中 isBodyless 的
        // 两个条件。com.sun.net.httpserver 发 204/304 时无法携带正长度实体，stale CL
        // 场景由 isBodyless 早退守卫（服务端带不带该头都不比对）。
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/nocontent", exchange -> exchange.sendResponseHeaders(204, -1));
        server.createContext("/notmodified", exchange -> exchange.sendResponseHeaders(304, -1));
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        TransportResponse noContent = transport.send(
                new RequestDraft("POST", "/nocontent", headers(), new byte[]{1}));
        assertEquals(204, noContent.statusCode());
        assertEquals(0, noContent.body().length);
        TransportResponse notModified = transport.send(
                new RequestDraft("POST", "/notmodified", headers(), new byte[]{1}));
        assertEquals(304, notModified.statusCode());
        assertEquals(0, notModified.body().length);
    }

    @Test
    void unauthorizedErrorEnvelopeBodyReadable() throws Exception {
        // 契约：401 认证错误的信封体必须可读。streaming 模式（setFixedLengthStreamingMode）
        // 下 JDK 遇 401/407 会断连并丢弃错误响应体（getErrorStream() 恒 null，长度校验
        // 误报"响应体被截断"），故请求体须走默认缓冲模式发送（wire 本就是内存 byte[]）。
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> {
            byte[] out = "{\"code\":\"OP_GW_1001\",\"message\":\"appKey 为空或应用不存在\"}"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        TransportResponse response = transport.send(
                new RequestDraft("POST", "/p", headers(), new byte[]{1}));
        assertEquals(401, response.statusCode());
        assertEquals("{\"code\":\"OP_GW_1001\",\"message\":\"appKey 为空或应用不存在\"}",
                new String(response.body(), java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void interruptedDuringResponseFails() throws Exception {
        // 中途中断：handler 在写响应前 interrupt 调用线程（HttpURLConnection 阻塞
        // I/O 本身不响应中断）→ 响应状态返回后的阶段边界检查命中并失败，
        // 对齐原 java.net.http 版「恢复标志并失败」的语义
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        final Thread caller = Thread.currentThread();
        server.createContext("/p", exchange -> {
            caller.interrupt();
            exchange.sendResponseHeaders(200, -1);
        });
        server.start();
        JdkHttpTransport transport = new JdkHttpTransport(
                "http://127.0.0.1:" + server.getAddress().getPort());
        try {
            WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(
                    new RequestDraft("POST", "/p", headers(), new byte[]{1})));
            assertTrue(ex.getMessage().contains("被中断"));
        } finally {
            Thread.interrupted();
        }
    }
}
