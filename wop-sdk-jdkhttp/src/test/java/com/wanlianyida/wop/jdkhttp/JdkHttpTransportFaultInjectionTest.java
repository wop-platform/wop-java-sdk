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

/**
 * 故障注入（JDK HttpURLConnection 适配器网络层）：中途断流/5xx 透传/头名规范化/
 * 无实体状态/错误状态空体/中途中断。
 * 连接拒收与发送前线程中断场景见 {@link JdkHttpTransportTest}（环境确定性更高）。
 */
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
        // 故障：声明 Content-Length=1000 但只写 10 字节即关闭 → IOException 包装为明确异常
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
        // 故障：网关 502 —— 适配器只做透传，状态语义由 verify 层/商户决定
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
        // 契约：适配器送入 verify 层的头名恒小写存储；TransportResponse 为大小写不敏感视图
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
        // 大小写不敏感视图：任意形态查询命中同一值；存储键恒小写
        assertEquals("WOP-RSA3072-SHA256 v1/1800/a/b", response.headers().get("X-WOP-SIGN"));
        assertTrue(response.headers().keySet().stream().allMatch(k -> k.equals(k.toLowerCase())));
    }

    @Test
    void emptyBodyResponseMappedToEmptyArray() throws Exception {
        // 204 无实体 → body 为空数组（verify 层按无 body 响应处理）
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
        // 故障：404 且服务器未写错误体（error stream 为 null）→ 按空 body 透传给
        // verify 层/商户；此时 getInputStream() 会抛 IOException，不可调用
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
            Thread.interrupted();   // 消费 interrupt 标志，避免污染后续测试
        }
    }
}
