package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.WopSdkException;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Proxy;
import java.util.LinkedHashMap;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 传输阶段打标：连接超时与读超时同为 {@link java.net.SocketTimeoutException}，
 * 只有阶段能区分二者——前者可 failover，后者不可（重发有重复副作用风险）。
 * <p>
 * 显式 {@link Proxy#NO_PROXY}：否则系统代理会把不可路由地址变成「连接成功」。
 */
class OkHttpTransportPhaseTest {

    private final MockWebServer server = new MockWebServer();

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    private static RequestDraft draft() {
        return new RequestDraft("POST", "/p", new LinkedHashMap<String, String>(), new byte[]{1});
    }

    @Test
    void connectTimeoutReportsConnectPhase() {
        OkHttpClient fast = new OkHttpClient.Builder()
                .proxy(Proxy.NO_PROXY)
                .connectTimeout(200, TimeUnit.MILLISECONDS)
                .readTimeout(200, TimeUnit.MILLISECONDS)
                .build();
        OkHttpTransport transport = new OkHttpTransport("http://10.255.255.1:81", fast);
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(draft()));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException, String.valueOf(ex.getCause()));
        assertEquals(WopSdkException.Phase.CONNECT, ex.phase());
    }

    @Test
    void readTimeoutReportsSentPhase() throws Exception {
        server.enqueue(new MockResponse().setHeadersDelay(2, TimeUnit.SECONDS).setBody("late"));
        server.start();
        OkHttpClient fast = new OkHttpClient.Builder()
                .proxy(Proxy.NO_PROXY)
                .connectTimeout(1, TimeUnit.SECONDS)
                .readTimeout(200, TimeUnit.MILLISECONDS)
                .build();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString(), fast);
        WopSdkException ex = assertThrows(WopSdkException.class, () -> transport.send(draft()));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException, String.valueOf(ex.getCause()));
        assertEquals(WopSdkException.Phase.SENT, ex.phase());
    }

    @Test
    void phaseTrackingIsPerCallNotSharedAcrossSends() throws Exception {
        // 打标状态按调用独立：前一次成功已把阶段推到 SENT，后一次连接超时必须重新从 CONNECT 起算。
        // 若阶段跨调用共享且不复位，第二次会残留 SENT，此断言即红。
        server.enqueue(new MockResponse().setBody("ok"));
        server.start();
        OkHttpClient client = new OkHttpClient.Builder()
                .proxy(Proxy.NO_PROXY)
                .connectTimeout(200, TimeUnit.MILLISECONDS)
                .readTimeout(200, TimeUnit.MILLISECONDS)
                .build();
        OkHttpTransport transport = new OkHttpTransport(server.url("/").toString(), client);
        assertEquals(200, transport.send(draft()).statusCode());
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> transport.send(draft(), TransportCall.of("http://10.255.255.1:81", 200, 200)));
        assertTrue(ex.getCause() instanceof java.net.SocketTimeoutException, String.valueOf(ex.getCause()));
        assertEquals(WopSdkException.Phase.CONNECT, ex.phase());
    }
}
