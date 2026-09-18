package com.wanlianyida.wop;

import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WopClient 边界：legacy（无 serverRoot）与 fromConfig 客户端的行为分界、
 * verifyResponse/verifyCallback 的 options 分支、Builder 守卫与变体。
 */
class WopClientEdgeTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String PRIMARY = "https://gw.example.com/gateway";

    private static final WopClientVerifyTest.PlatformRig RIG =
            new WopClientVerifyTest.PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);

    /** 记录 send 入参并回放固定响应的传输。 */
    private static final class RecordingTransport implements Transport {
        final TransportResponse response;
        TransportCall seenCall;
        RequestDraft seenDraft;

        RecordingTransport(TransportResponse response) {
            this.response = response;
        }

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
            this.seenCall = call;
            this.seenDraft = draft;
            return response;
        }
    }

    private static WopSdkConfig config(Transport transport) {
        return new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot(PRIMARY)
                .transport(transport)
                .build();
    }

    private static WopClient legacyClient() {
        return WopClient.builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .build();
    }

    @Test
    void executeFourArgFromConfigInterceptsNon2xx() {
        RecordingTransport stub = new RecordingTransport(
                new TransportResponse(500, Collections.emptyMap(), new byte[0]));
        WopClient client = WopClient.fromConfig(config(stub));
        WopGatewayResponseException e = assertThrows(WopGatewayResponseException.class,
                () -> client.execute("POST", "/gateway/x", Codec.utf8("{}"), SecurityLevel.L0));
        assertEquals(500, e.statusCode());
        assertEquals(PRIMARY, stub.seenCall.serverRoot());
    }

    @Test
    void executeFiveArgCarriesTimeoutOverride() {
        RecordingTransport stub = new RecordingTransport(
                new TransportResponse(500, Collections.emptyMap(), new byte[0]));
        WopClient client = WopClient.fromConfig(config(stub));
        assertThrows(WopGatewayResponseException.class, () -> client.execute("POST", "/gateway/x",
                Codec.utf8("{}"), SecurityLevel.L0,
                WopRequestOptions.builder().connectTimeout(2500).build()));
        assertEquals(2500, stub.seenCall.connectTimeoutMillis());
        assertEquals(30000, stub.seenCall.readTimeoutMillis());
    }

    @Test
    void legacyClientExecuteRejected() {
        WopError e = assertThrows(WopError.class, () -> legacyClient()
                .execute("POST", "/gateway/x", Codec.utf8("{}"), SecurityLevel.L0));
        assertTrue(e.getMessage().contains("execute 需要经 fromConfig/defaultClient 构造的客户端"),
                e.getMessage());
    }

    @Test
    void buildRequestGuards() {
        WopClient client = legacyClient();
        byte[] body = Codec.utf8("{}");
        assertTrue(assertThrows(WopError.class,
                        () -> client.buildRequest("", "/p", body, SecurityLevel.L0))
                .getMessage().contains("HTTP method 为空"));
        assertTrue(assertThrows(WopError.class,
                        () -> client.buildRequest("POST", "/p", body, null))
                .getMessage().contains("SecurityLevel 为空"));
        assertTrue(assertThrows(WopError.class,
                        () -> client.buildRequest("POST", "/p", null, SecurityLevel.L2))
                .getMessage().contains("L2 加密需要非空 body"));
    }

    @Test
    void legacyBuildRequestWithoutOptionsWorks() {
        RequestDraft draft = legacyClient()
                .buildRequest("POST", "/p", Codec.utf8("{}"), SecurityLevel.L0);
        assertEquals("POST", draft.method());
        assertEquals("/p", draft.path());
    }

    @Test
    void legacyBuildRequestWithOptionsRejected() {
        WopError e = assertThrows(WopError.class, () -> legacyClient().buildRequest(
                "POST", "/p", Codec.utf8("{}"), SecurityLevel.L0,
                WopRequestOptions.builder().appKey("x").build()));
        assertTrue(e.getMessage().contains("请求级覆盖需要经 fromConfig/defaultClient 构造的客户端"),
                e.getMessage());
    }

    @Test
    void legacyVerifyResponseWithOptionsRejected() {
        WopError e = assertThrows(WopError.class, () -> legacyClient().verifyResponse(
                Collections.emptyMap(), Codec.utf8("x"), "/p",
                WopRequestOptions.builder().appKey("x").build()));
        assertTrue(e.getMessage().contains("凭证覆盖需要经 fromConfig 构造的客户端"), e.getMessage());
    }

    @Test
    void legacyVerifyResponseWithNullAndNoneOptionsFailsSoft() {
        WopClient client = legacyClient();
        for (WopRequestOptions options : new WopRequestOptions[]{null, WopRequestOptions.none()}) {
            VerifyResult result = client.verifyResponse(
                    Collections.emptyMap(), Codec.utf8("x"), "/p", options);
            assertFalse(result.ok());
            assertEquals(VerifyResult.Reason.MISSING_SIGN_HEADER, result.reason());
        }
    }

    @Test
    void verifyResponseWithOptionsUsesGlobalCredentials() {
        byte[] plain = Codec.utf8("{\"ok\":true}");
        WopClientVerifyTest.PlatformResponse resp = RIG.respond("/gateway/x", plain, false);
        WopClient client = WopClient.fromConfig(config(
                d -> new TransportResponse(200, Collections.emptyMap(), new byte[0])));
        VerifyResult result = client.verifyResponse(resp.headers(), plain, "/gateway/x",
                WopRequestOptions.builder().connectTimeout(2500).build());
        assertTrue(result.ok(), () -> result.toString());
    }

    @Test
    void verifyResponseTransportDelegation() {
        byte[] plain = Codec.utf8("{\"ok\":true}");
        WopClientVerifyTest.PlatformResponse resp = RIG.respond("/gateway/x", plain, false);
        WopClient client = WopClient.fromConfig(config(
                d -> new TransportResponse(200, Collections.emptyMap(), new byte[0])));
        RequestDraft draft = client.buildRequest("POST", "/gateway/x", plain, SecurityLevel.L0);
        assertNotNull(draft);
        TransportResponse wire = new TransportResponse(200, resp.headers(), plain);
        assertTrue(client.verifyResponse(wire, draft).ok());
        assertTrue(client.verifyResponse(wire, draft,
                WopRequestOptions.builder().connectTimeout(2500).build()).ok());
    }

    @Test
    void legacyVerifyCallbackNullOptionsFailsSoft() {
        VerifyResult result = legacyClient().verifyCallback(
                Collections.emptyMap(), Codec.utf8("x"), "/cb", null);
        assertFalse(result.ok());
        assertEquals(VerifyResult.Reason.MISSING_SIGN_HEADER, result.reason());
    }

    @Test
    void legacyVerifyCallbackWithOptionsRejected() {
        WopError e = assertThrows(WopError.class, () -> legacyClient().verifyCallback(
                Collections.emptyMap(), Codec.utf8("x"), "/cb",
                WopRequestOptions.builder().appKey("x").build()));
        assertTrue(e.getMessage().contains("verifyCallback 凭证覆盖需要经 fromConfig 构造的客户端"),
                e.getMessage());
    }

    @Test
    void verifyCallbackWithTransportOnlyOptionsStillVerifies() {
        byte[] plain = Codec.utf8("{\"eventId\":\"e1\"}");
        WopClientVerifyTest.PlatformResponse resp = RIG.respond("/merchant/callback", plain, false);
        WopClient client = WopClient.fromConfig(config(
                d -> new TransportResponse(200, Collections.emptyMap(), new byte[0])));
        VerifyResult result = client.verifyCallback(resp.headers(), plain, "/merchant/callback",
                WopRequestOptions.builder().readTimeout(3500).build());
        assertTrue(result.ok(), () -> result.toString());
    }

    @Test
    void executeVerifiesRigResponseWithTransportLevelOptions() {
        byte[] plain = Codec.utf8("{\"ok\":true}");
        WopClientVerifyTest.PlatformResponse resp = RIG.respond("/gateway/x", plain, false);
        RecordingTransport stub = new RecordingTransport(
                new TransportResponse(200, resp.headers(), plain));
        WopClient client = WopClient.fromConfig(config(stub));
        VerifyResult result = client.execute("POST", "/gateway/x", plain, SecurityLevel.L0,
                WopRequestOptions.builder().connectTimeout(2500).build());
        assertTrue(result.ok(), () -> result.toString());
        assertEquals(2500, stub.seenCall.connectTimeoutMillis());
    }

    @Test
    void builderVariantsProduceUsableClients() {
        byte[] plain = Codec.utf8("{\"ok\":true}");
        WopClientVerifyTest.PlatformResponse resp = RIG.respond("/gateway/x", plain, false);
        RecordingTransport stub = new RecordingTransport(
                new TransportResponse(200, resp.headers(), plain));

        WopClient nullBackups = WopClient.builder()
                .appKey("app_001").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB)
                .serverRoot(PRIMARY)
                .backupServerRoots((String[]) null)
                .transport(stub)
                .build();
        assertTrue(nullBackups.execute("POST", "/gateway/x", plain, SecurityLevel.L0).ok());

        WopClient singleBackup = WopClient.builder()
                .appKey("app_001").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB)
                .serverRoot(PRIMARY)
                .backupServerRoots("https://b.example.com/gateway")
                .transport(stub)
                .build();
        assertTrue(singleBackup.execute("POST", "/gateway/x", plain, SecurityLevel.L0).ok());

        WopClient httpNull = WopClient.builder()
                .appKey("app_001").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB)
                .serverRoot(PRIMARY)
                .httpClient(null)
                .transport(stub)
                .build();
        assertTrue(httpNull.execute("POST", "/gateway/x", plain, SecurityLevel.L0).ok());

        // serverRoot 仅有空白 → legacy 客户端，execute 拒绝
        WopClient blankRoot = WopClient.builder()
                .appKey("app_001").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB)
                .serverRoot("   ")
                .transport(stub)
                .build();
        assertThrows(WopError.class,
                () -> blankRoot.execute("POST", "/gateway/x", plain, SecurityLevel.L0));
    }

    @Test
    void builderFailsFastOnMissingPieces() {
        assertTrue(assertThrows(WopError.class, () -> WopClient.builder()
                        .suite("WOP-RSA3072-SHA256").build())
                .getMessage().contains("appKey 为空"));
        assertTrue(assertThrows(WopError.class, () -> WopClient.builder()
                        .appKey("app_001").build())
                .getMessage().contains("suite（securityReq）为空"));
        assertTrue(assertThrows(WopError.class, () -> WopClient.builder()
                        .appKey("app_001").suite("WOP-RSA3072-SHA256").expiredSeconds(0L).build())
                .getMessage().contains("expiredSeconds 须为正整数"));
        assertThrows(WopError.class, () -> WopClient.builder()
                .appKey("app_001").suite("WOP-NOPE").build());
        assertTrue(assertThrows(WopError.class, () -> WopClient.builder()
                        .appKey("app_001").suite("WOP-RSA3072-SHA256").platformPublicKey(RSA_PUB).build())
                .getMessage().contains("merchantPrivateKey 为空"));
        assertTrue(assertThrows(WopError.class, () -> WopClient.builder()
                        .appKey("app_001").suite("WOP-RSA3072-SHA256").merchantPrivateKey(RSA_PRIV).build())
                .getMessage().contains("platformPublicKey 为空"));
    }

    @Test
    void executeInterceptsInformationalStatus() {
        // 1xx（< 200）同样不属于成功区间 → WopGatewayResponseException
        RecordingTransport stub = new RecordingTransport(
                new TransportResponse(199, Collections.emptyMap(), new byte[0]));
        WopClient client = WopClient.fromConfig(config(stub));
        WopGatewayResponseException e = assertThrows(WopGatewayResponseException.class,
                () -> client.execute("POST", "/gateway/x", Codec.utf8("{}"), SecurityLevel.L0));
        assertEquals(199, e.statusCode());
    }

    @Test
    void buildRequestWithNullOptionsMatchesNone() {
        RequestDraft draft = WopClient.fromConfig(config(
                        d -> new TransportResponse(200, Collections.emptyMap(), new byte[0])))
                .buildRequest("POST", "/p", Codec.utf8("{}"), SecurityLevel.L0, null);
        assertEquals("POST", draft.method());
        assertEquals("/p", draft.path());
    }

    @Test
    void executeWithNullOptionsUsesDefaultContext() {
        byte[] plain = Codec.utf8("{\"ok\":true}");
        WopClientVerifyTest.PlatformResponse resp = RIG.respond("/gateway/x", plain, false);
        RecordingTransport stub = new RecordingTransport(
                new TransportResponse(200, resp.headers(), plain));
        WopClient client = WopClient.fromConfig(config(stub));
        VerifyResult result = client.execute("POST", "/gateway/x", plain, SecurityLevel.L0, null);
        assertTrue(result.ok(), () -> result.toString());
    }
}
