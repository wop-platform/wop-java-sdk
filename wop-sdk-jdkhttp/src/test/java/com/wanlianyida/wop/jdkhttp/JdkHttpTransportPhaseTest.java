package com.wanlianyida.wop.jdkhttp;

import com.sun.net.httpserver.HttpServer;
import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.WopSdkException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 传输阶段打标：连接超时与读超时同为 {@link java.net.SocketTimeoutException}，
 * 只有阶段边界（{@code connect()} 返回）能区分二者。
 * <p>
 * 全部用例强制 {@link Proxy#NO_PROXY}：系统代理会把不可路由地址变成「连接成功」，
 * 使连接超时用例在本机静默失效。HTTP_PROXY 环境变量故保留 try/finally 还原。
 */
class JdkHttpTransportPhaseTest {

    private HttpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static RequestDraft draft() {
        return new RequestDraft("POST", "/p", new LinkedHashMap<String, String>(), new byte[]{1});
    }

    private static TransportCall fastCall(String root) {
        return TransportCall.of(root, 300, 300);
    }

    /** 在禁代理上下文中执行：否则 http.proxyHost 会把连接劫持成功。 */
    private static <T> T withoutProxy(ThrowingSupplier<T> body) throws Exception {
        ProxySelector original = ProxySelector.getDefault();
        ProxySelector.setDefault(new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            }
        });
        try {
            return body.get();
        } finally {
            ProxySelector.setDefault(original);
        }
    }

    interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    @Test
    void connectTimeoutReportsConnectPhase() throws Exception {
        String root = "http://10.255.255.1:81";
        WopSdkException ex = withoutProxy(() -> assertThrows(WopSdkException.class,
                () -> new JdkHttpTransport().send(draft(), fastCall(root))));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException, String.valueOf(ex.getCause()));
        assertEquals(WopSdkException.Phase.CONNECT, ex.phase());
    }

    @Test
    void readTimeoutReportsSentPhase() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> {
            sleep(1_500);
            exchange.sendResponseHeaders(200, -1);
        });
        server.start();
        String root = "http://127.0.0.1:" + server.getAddress().getPort();
        WopSdkException ex = withoutProxy(() -> assertThrows(WopSdkException.class,
                () -> new JdkHttpTransport().send(draft(), fastCall(root))));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException, String.valueOf(ex.getCause()));
        assertEquals(WopSdkException.Phase.SENT, ex.phase());
    }

    @Test
    void connectionRefusedReportsConnectPhase() {
        // 127.0.0.1 未监听端口：拒绝连接发生在 connect() 内，请求体未写出
        int port = freePort();
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> new JdkHttpTransport().send(draft(), fastCall("http://127.0.0.1:" + port)));
        assertEquals(WopSdkException.Phase.CONNECT, ex.phase());
    }

    @Test
    void getRequestAlsoMarkedSentAfterConnect() throws Exception {
        // GET 无实体：connect() 后到 getResponseCode() 之间已进入发送阶段
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/p", exchange -> {
            sleep(1_500);
            exchange.sendResponseHeaders(200, -1);
        });
        server.start();
        String root = "http://127.0.0.1:" + server.getAddress().getPort();
        WopSdkException ex = withoutProxy(() -> assertThrows(WopSdkException.class,
                () -> new JdkHttpTransport().send(
                        new RequestDraft("GET", "/p", new LinkedHashMap<String, String>(), null),
                        fastCall(root))));
        assertEquals(WopSdkException.Phase.SENT, ex.phase());
    }

    private static int freePort() {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
