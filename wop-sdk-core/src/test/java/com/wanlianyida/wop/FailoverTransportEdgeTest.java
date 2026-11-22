package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopRequestContext;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.net.UnknownHostException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.util.Collections;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * FailoverTransport 补充边界：单参 send、mergeCall 合并语义（引用判 empty 与超时保留）、
 * 非重试异常原样上抛、isPreSendRetryable 分类。
 */
class FailoverTransportEdgeTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String PRIMARY = "https://primary.example.com/gateway";

    private static WopRequestContext context(int maxRetry) {
        WopSdkConfig cfg = new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot(PRIMARY)
                .backupServerRoots("https://backup.example.com/gateway")
                .httpClient(new HttpClientSettings(10_000, 30_000, maxRetry))
                .build();
        return WopRequestContext.resolve(cfg, WopRequestOptions.none());
    }

    private static RequestDraft draft() {
        return new RequestDraft("POST", "/gateway/x", new LinkedHashMap<String, String>(), null);
    }

    /** 记录合并后 TransportCall 的直通传输。 */
    private static final class RecordingTransport implements Transport {
        TransportCall seenCall;

        @Override
        public boolean supportsTransportCall() {
            return true;
        }

        @Override
        public TransportResponse send(RequestDraft d) {
            return send(d, TransportCall.empty());
        }

        @Override
        public TransportResponse send(RequestDraft d, TransportCall call) {
            this.seenCall = call;
            return new TransportResponse(200, Collections.emptyMap(), new byte[0]);
        }
    }

    @Test
    void singleArgSendTargetsPrimaryWithDefaults() {
        RecordingTransport delegate = new RecordingTransport();
        TransportResponse resp = new FailoverTransport(delegate, context(3)).send(draft());
        assertEquals(200, resp.statusCode());
        assertEquals(TransportCall.of(PRIMARY, TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT),
                delegate.seenCall);
    }

    @Test
    void nullCallMergesPrimaryRoot() {
        RecordingTransport delegate = new RecordingTransport();
        new FailoverTransport(delegate, context(3)).send(draft(), null);
        assertEquals(TransportCall.of(PRIMARY, TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT),
                delegate.seenCall);
    }

    @Test
    void valueEqualToEmptyStillTakesExplicitPath() {
        // 仅 null 走默认分支；值等 empty() 的显式 call 按字段合并，结果值等
        RecordingTransport delegate = new RecordingTransport();
        new FailoverTransport(delegate, context(3)).send(draft(),
                TransportCall.of(null, TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT));
        assertEquals(TransportCall.of(PRIMARY, TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT),
                delegate.seenCall);
    }

    @Test
    void callTimeoutsPreservedAcrossMerge() {
        RecordingTransport delegate = new RecordingTransport();
        new FailoverTransport(delegate, context(3)).send(draft(), TransportCall.of("ignored", 1500, 2500));
        assertEquals(TransportCall.of(PRIMARY, 1500, 2500), delegate.seenCall);
    }

    @Test
    void nonRetryableFailurePropagatesAsIs() {
        final WopSdkException failure = new WopSdkException("协议错误", new IllegalStateException("x"));
        Transport delegate = new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft d) {
                throw failure;
            }

            @Override
            public TransportResponse send(RequestDraft d, TransportCall call) {
                return send(d);
            }
        };
        WopSdkException caught = assertThrows(WopSdkException.class,
                () -> new FailoverTransport(delegate, context(3)).send(draft(), TransportCall.empty()));
        assertSame(failure, caught);
    }

    @Test
    void preSendRetryableClassification() {
        assertTrue(FailoverTransport.isPreSendRetryable(
                new WopSdkException("x", new UnknownHostException("h"))));
        assertTrue(FailoverTransport.isPreSendRetryable(
                new WopSdkException("x", new NoRouteToHostException("h"))));
        assertTrue(FailoverTransport.isPreSendRetryable(new WopSdkException("a",
                new WopSdkException("b", new ConnectException("refused")))));
        assertFalse(FailoverTransport.isPreSendRetryable(new WopSdkException("x")));
        assertFalse(FailoverTransport.isPreSendRetryable(
                new WopSdkException("x", new IllegalStateException("x"))));
    }
}
