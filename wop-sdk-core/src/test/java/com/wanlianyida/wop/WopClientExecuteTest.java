package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P1：execute 双参、非 2xx、verifyCallback 凭证覆盖。 */
class WopClientExecuteTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static Transport stubTransport(TransportResponse response) {
        return new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft draft) {
                return send(draft, TransportCall.empty());
            }

            @Override
            public TransportResponse send(RequestDraft draft, TransportCall call) {
                return response;
            }
        };
    }

    private static WopSdkConfig configWithTransport(Transport transport) {
        return new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .expiredSeconds(1800L)
                .httpClient(HttpClientSettings.defaults())
                .transport(transport)
                .build();
    }

    @Test
    void redirectStatusDoesNotEnterVerify() {
        Transport transport = stubTransport(
                new TransportResponse(302, Collections.emptyMap(), "moved".getBytes()));
        WopClient client = WopClient.fromConfig(configWithTransport(transport));
        WopGatewayResponseException ex = assertThrows(WopGatewayResponseException.class,
                () -> client.execute("POST", "/gateway/x", "{}".getBytes(), SecurityLevel.L0));
        assertEquals(302, ex.statusCode());
    }

    @Test
    void non2xxThrowsGatewayException() {
        Transport transport = stubTransport(
                new TransportResponse(502, Collections.emptyMap(), "bad".getBytes()));
        WopClient client = WopClient.fromConfig(configWithTransport(transport));
        WopGatewayResponseException ex = assertThrows(WopGatewayResponseException.class,
                () -> client.execute("POST", "/gateway/x", "{}".getBytes(), SecurityLevel.L0));
        assertEquals(502, ex.statusCode());
        assertEquals("bad", new String(ex.body()));
    }

    @Test
    void executeWithOptionsRequiresFromConfigClient() {
        WopClient builderClient = WopClient.builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .build();
        WopError error = assertThrows(WopError.class, () -> builderClient.execute(
                "POST", "/gateway/x", "{}".getBytes(), SecurityLevel.L0,
                WopRequestOptions.builder().appKey("other").build()));
        assertTrue(error.getMessage().contains("fromConfig") || error.getMessage().contains("凭证覆盖"));
    }

    @Test
    void executeUsesRequestLevelServerRoot() {
        AtomicReference<String> seenRoot = new AtomicReference<>();
        Transport transport = new Transport() {
            @Override
            public boolean supportsTransportCall() {
                return true;
            }

            @Override
            public TransportResponse send(RequestDraft draft) {
                return send(draft, TransportCall.empty());
            }

            @Override
            public TransportResponse send(RequestDraft draft, TransportCall call) {
                seenRoot.set(call.serverRoot());
                return new TransportResponse(500, Collections.emptyMap(), new byte[0]);
            }
        };
        WopClient client = WopClient.fromConfig(configWithTransport(transport));
        assertThrows(WopGatewayResponseException.class, () -> client.execute(
                "POST", "/gateway/x", "{}".getBytes(), SecurityLevel.L0,
                WopRequestOptions.builder().serverRoot("https://alt.example.com/gateway").build()));
        assertEquals("https://alt.example.com/gateway", seenRoot.get());
    }

    @Test
    void executeAcceptsEmptyBuiltOptions() {
        WopClient client = WopClient.fromConfig(configWithTransport(
                stubTransport(new TransportResponse(502, Collections.emptyMap(), new byte[0]))));
        assertThrows(WopGatewayResponseException.class, () -> client.execute(
                "POST", "/gateway/x", "{}".getBytes(), SecurityLevel.L0,
                WopRequestOptions.builder().build()));
    }

    @Test
    void verifyCallbackCredentialOverrideRequiresFromConfig() {
        WopClient builderClient = WopClient.builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .build();
        Map<String, String> headers = new LinkedHashMap<>();
        WopError error = assertThrows(WopError.class, () -> builderClient.verifyCallback(
                headers, new byte[0], "/cb",
                WopRequestOptions.builder().platformPublicKey(RSA_PUB).build()));
        assertTrue(error.getMessage().contains("fromConfig") || error.getMessage().contains("凭证覆盖"));
    }
}
