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
 * 故障注入（JDK HttpClient 适配器网络层）：中途断流/5xx 透传/头名规范化/204 无实体。
 * 连接拒收与线程中断场景见 {@link JdkHttpTransportTest}（环境确定性更高）。
 */
class JdkHttpTransportFaultInjectionTest {

    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
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
                new RequestDraft("POST", "/cut", Map.of(), new byte[]{1})));
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
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
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
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
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
                new RequestDraft("POST", "/p", Map.of(), new byte[]{1}));
        assertEquals(204, response.statusCode());
        assertEquals(0, response.body().length);
    }
}
