package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.CanonicalRequest;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.DekPayload;
import com.wanlianyida.wop.crypto.EncryptHeader;
import com.wanlianyida.wop.crypto.SignHeader;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WopClientBuildRequestTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String RSA4096_PUB = TestVectors.keys("rsa4096").path("publicSpkiB64").asText();

    private static WopClient fixedClient(Supplier<String> nonce) {
        LongSupplier clock = () -> 1_758_900_000_000L;
        return testClient("WOP-RSA3072-SHA256", nonce, clock);
    }

    /** 固定 clock/nonce/requestIdGen 的测试客户端（附录 I/I3 注入锚：全头字节级可重放）。 */
    private static WopClient fixedClient(Supplier<String> nonce, Supplier<String> requestIdGen) {
        LongSupplier clock = () -> 1_758_900_000_000L;
        return new WopClient(new WopClient.Config(
                "app_001", AlgorithmSuite.parse("WOP-RSA3072-SHA256"),
                RSA_PRIV, RSA_PUB, 1800), clock, nonce, requestIdGen, new SecureRandom());
    }

    static WopClient testClient(String suite, Supplier<String> nonce, LongSupplier clock) {
        return new WopClient(new WopClient.Config(
                "app_001", AlgorithmSuite.parse(suite),
                RSA_PRIV, RSA_PUB, 1800), clock, nonce);
    }

    private static WopClient fromConfigClient() {
        WopSdkConfig cfg = new WopSdkConfig.Builder()
                .appKey("app_001")
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .serverRoot("https://gw.example.com/gateway")
                .expiredSeconds(1800L)
                .httpClient(HttpClientSettings.defaults())
                .transport(draft -> new TransportResponse(200, Collections.emptyMap(), new byte[0]))
                .build();
        return WopClient.fromConfig(cfg);
    }

    private static final Supplier<String> NONCE = () -> "fixed00000000000000000000000000a";

    @Test
    void builderRequiresMandatoryFields() {
        assertThrows(WopError.class, () -> WopClient.builder().build());
        assertThrows(WopError.class, () -> WopClient.builder().appKey("a").build());
        assertThrows(WopError.class, () -> WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256").build());
        WopClient.Builder partial = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV);
        assertThrows(WopError.class, partial::build);
        assertThrows(WopError.class, () -> WopClient.builder().appKey("a")
                .suite("WOP-RSA3072-SM3").merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build());
        assertThrows(WopError.class, () -> WopClient.builder().appKey("a")
                .suite("WOP-RSA4096-SHA256").merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build());
        assertThrows(WopError.class, () -> WopClient.builder().appKey("a")
                .suite("WOP-RSA3072-SHA256").merchantPrivateKey("!!!").platformPublicKey(RSA_PUB).build());
    }

    @Test
    void builderAcceptsPemAndBase64() {
        String pem = "-----BEGIN PUBLIC KEY-----\n" + RSA_PUB + "\n-----END PUBLIC KEY-----\n";
        assertNotNull(WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(pem).build());
    }

    @Test
    void l0GetWithoutBodyOmitsDigest() {
        WopClient client = fixedClient(NONCE);
        RequestDraft draft = client.buildRequest("GET", "/gateway/order/get", null, SecurityLevel.L0);
        assertNull(draft.headers().get("x-wop-content-digest"));
        assertNull(draft.headers().get("x-wop-encrypt"));
        assertNull(draft.wireBody());
        assertEquals("GET", draft.method());

        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals("WOP-RSA3072-SHA256", sign.securityReq());
        assertEquals(1800, sign.expiredSeconds());
        // 基础头必签；无 body 时 digest 不在 signedHeaders
        assertEquals(java.util.Arrays.asList("x-wop-appkey", "x-wop-nonce", "x-wop-timestamp"), sign.signedHeaders());
        assertEquals("1_758_900_000_000".replace("_", ""), draft.headers().get("x-wop-timestamp"));
        assertEquals(NONCE.get(), draft.headers().get("x-wop-nonce"));
        // AC-20 零回归：未传 subMchId 时该头缺席
        assertNull(draft.headers().get("x-wop-sub-mch-id"));
    }

    @Test
    void l0PostWithBodySignsDigest() {
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{\"orderId\":\"W1\"}");
        RequestDraft draft = client.buildRequest("POST", "/gateway/order/create", body, SecurityLevel.L0);

        String digest = draft.headers().get("x-wop-content-digest");
        String expected = "sha-256 " + Codec.hexLower(
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").digest().digest(body));
        assertEquals(expected, digest);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-content-digest"));
        assertArrayEquals(body, draft.wireBody());

        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
    }

    @Test
    void subMchIdHeaderSignedL0WithBody() {
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{\"k\":1}");
        RequestDraft draft = client.buildRequest("POST", "/gateway/order/create", body, SecurityLevel.L0,
                WopRequestOptions.builder().subMchId("PLF-SUB-001").build());

        assertEquals("PLF-SUB-001", draft.headers().get("x-wop-sub-mch-id"));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        // TreeSet 字典序：digest 与子商户头均入签
        assertEquals(java.util.Arrays.asList("x-wop-appkey", "x-wop-content-digest",
                "x-wop-nonce", "x-wop-sub-mch-id", "x-wop-timestamp"), sign.signedHeaders());
        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
    }

    @Test
    void subMchIdHeaderSignedL0WithoutBody() {
        WopClient client = fixedClient(NONCE);
        RequestDraft draft = client.buildRequest("GET", "/gateway/order/get", null, SecurityLevel.L0,
                WopRequestOptions.builder().subMchId("PLF-SUB-001").build());

        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(java.util.Arrays.asList("x-wop-appkey", "x-wop-nonce",
                "x-wop-sub-mch-id", "x-wop-timestamp"), sign.signedHeaders());
        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
    }

    @Test
    void subMchIdHeaderSignedL2() {
        WopClient client = fixedClient(NONCE);
        RequestDraft draft = client.buildRequest("POST", "/gateway/pay", Codec.utf8("{\"amount\":100}"),
                SecurityLevel.L2, WopRequestOptions.builder().subMchId("PLF-SUB-001").build());

        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(java.util.Arrays.asList("x-wop-appkey", "x-wop-content-digest", "x-wop-encrypt",
                "x-wop-nonce", "x-wop-sub-mch-id", "x-wop-timestamp"), sign.signedHeaders());
        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
    }

    @Test
    void subMchIdSignedWhileRequestIdStaysUnsigned() {
        WopClient client = fixedClient(NONCE, () -> "fixedreq000000000000000000000001");
        RequestDraft draft = client.buildRequest("GET", "/gateway/order/get", null, SecurityLevel.L0,
                WopRequestOptions.builder().subMchId("PLF-SUB-001").requestId("req-042").build());

        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-sub-mch-id"));
        assertFalse(sign.signedHeaders().contains("x-wop-request-id"));
        assertEquals("req-042", draft.headers().get("x-wop-request-id"));
        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
    }

    @Test
    void subMchIdTrimsAndBlankKeepsHeadersByteIdentical() {
        WopClient client = fixedClient(NONCE, () -> "fixedreq000000000000000000000001");
        byte[] body = Codec.utf8("{\"k\":1}");
        RequestDraft plain = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0);
        RequestDraft blank = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0,
                WopRequestOptions.builder().subMchId("   ").build());
        assertEquals(plain.headers(), blank.headers());
        assertNull(blank.headers().get("x-wop-sub-mch-id"));
        // 首尾空白 trim 后上行（与网关 lookup 的 trim 一致）
        RequestDraft trimmed = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0,
                WopRequestOptions.builder().subMchId("  PLF-SUB-001  ").build());
        assertEquals("PLF-SUB-001", trimmed.headers().get("x-wop-sub-mch-id"));
    }

    @Test
    void l2EncryptsBodyAndWrapsDekWithPlatformKey() throws Exception {
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{\"amount\":100}");
        RequestDraft draft = client.buildRequest("POST", "/gateway/pay", body, SecurityLevel.L2);

        // wire body = {"encrypted":"<b64url>"}
        String wire = new String(draft.wireBody(), StandardCharsets.UTF_8);
        assertTrue(wire.startsWith("{\"encrypted\":\"") && wire.endsWith("\"}"), wire);
        byte[] cipherB64u = Codec.utf8(wire.substring(14, wire.length() - 2));

        String digest = draft.headers().get("x-wop-content-digest");
        assertEquals("sha-256 " + Codec.hexLower(
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").digest().digest(draft.wireBody())), digest);

        // x-wop-encrypt 存在且入签（I1 同级规则）
        String encryptHeader = draft.headers().get("x-wop-encrypt");
        assertTrue(encryptHeader.startsWith("L2;dek="));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-encrypt"));
        // AC-20 零回归：未传 subMchId 时该头缺席
        assertNull(draft.headers().get("x-wop-sub-mch-id"));

        com.wanlianyida.wop.crypto.EncryptHeader.Parsed parsed = EncryptHeader.parse(encryptHeader);
        PrivateKey platformPriv = com.wanlianyida.wop.crypto.KeyCodec.parsePrivateKey(
                TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(),
                AlgorithmSuite.parse("WOP-RSA3072-SHA256"));
        DekPayload dek = DekPayload.decode(new String(
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").keyEncrypt()
                        .decrypt(Codec.b64UrlDecode(parsed.dek()), platformPriv),
                StandardCharsets.UTF_8));
        assertEquals("AES-256-GCM", dek.alg());
        byte[] plain = AlgorithmSuite.parse("WOP-RSA3072-SHA256").messageEncrypt()
                .decrypt(Codec.b64UrlDecode(new String(cipherB64u, StandardCharsets.UTF_8)), dek.iv(), dek.key());
        assertArrayEquals(body, plain);

        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
    }

    @Test
    void l2Sm2SuiteUsesSm4GcmAndC1c3c2() throws Exception {
        WopClient client = new WopClient(new WopClient.Config(
                "app_sm2", AlgorithmSuite.parse("WOP-SM2-SM3"),
                TestVectors.keys("sm2").path("privateDB64").asText(),
                TestVectors.keys("sm2").path("publicPointB64").asText(), 1800),
                () -> 1L, NONCE);
        byte[] body = Codec.utf8("SM2 payload");
        RequestDraft draft = client.buildRequest("POST", "/gw/sm2", body, SecurityLevel.L2);

        String encryptHeader = draft.headers().get("x-wop-encrypt");
        com.wanlianyida.wop.crypto.EncryptHeader.Parsed parsed = EncryptHeader.parse(encryptHeader);
        PrivateKey priv = com.wanlianyida.wop.crypto.KeyCodec.parsePrivateKey(
                TestVectors.keys("sm2").path("privateDB64").asText(), AlgorithmSuite.parse("WOP-SM2-SM3"));
        byte[] dekPlain = AlgorithmSuite.parse("WOP-SM2-SM3").keyEncrypt()
                .decrypt(Codec.b64UrlDecode(parsed.dek()), priv);
        DekPayload dek = DekPayload.decode(new String(dekPlain, StandardCharsets.UTF_8));
        assertEquals("SM4-GCM", dek.alg());
        assertEquals(16, dek.key().length);
        assertTrue(draft.headers().get("x-wop-content-digest").startsWith("sm3 "));
        String wire = new String(draft.wireBody(), StandardCharsets.UTF_8);
        byte[] cipher = Codec.b64UrlDecode(wire.substring(14, wire.length() - 2));
        assertArrayEquals(body, AlgorithmSuite.parse("WOP-SM2-SM3").messageEncrypt()
                .decrypt(cipher, dek.iv(), dek.key()));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(86, sign.signature().length());
        PublicKey merchantPub = com.wanlianyida.wop.crypto.KeyCodec.parsePublicKey(
                TestVectors.keys("sm2").path("publicPointB64").asText(), AlgorithmSuite.parse("WOP-SM2-SM3"));
        assertTrue(signatureVerifies(draft, sign, merchantPub));
    }

    @Test
    void deterministicReplayWithFixedClockAndNonce() {
        WopClient client = fixedClient(NONCE, () -> "fixedreq000000000000000000000001");
        byte[] body = Codec.utf8("{\"k\":1}");
        RequestDraft a = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0);
        RequestDraft b = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0);
        assertEquals(a.headers(), b.headers());
        assertArrayEquals(a.wireBody(), b.wireBody());
        assertEquals("fixedreq000000000000000000000001", a.headers().get("x-wop-request-id"));

        RequestDraft c = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L2);
        RequestDraft d = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L2);
        assertEquals(c.headers().get("x-wop-appkey"), d.headers().get("x-wop-appkey"));
        assertEquals(c.headers().get("x-wop-nonce"), d.headers().get("x-wop-nonce"));
        assertNotEquals(c.headers().get("x-wop-content-digest"), d.headers().get("x-wop-content-digest"));
        assertNotEquals(c.headers().get("x-wop-encrypt"), d.headers().get("x-wop-encrypt"));
    }

    @Test
    void defaultNonceIs32HexAndFresh() {
        WopClient client = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build();
        RequestDraft a = client.buildRequest("GET", "/p", null, SecurityLevel.L0);
        RequestDraft b = client.buildRequest("GET", "/p", null, SecurityLevel.L0);
        assertEquals(32, a.headers().get("x-wop-nonce").length());
        assertTrue(a.headers().get("x-wop-nonce").matches("[0-9a-f]{32}"));
        assertNotEquals(a.headers().get("x-wop-nonce"), b.headers().get("x-wop-nonce"));
        assertTrue(a.headers().get("x-wop-timestamp").matches("\\d{13}"));
    }

    @Test
    void rejectsInvalidBuildRequestArguments() {
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{}");
        WopError e1 = assertThrows(WopError.class, () -> client.buildRequest(" ", "/p", body, SecurityLevel.L0));
        assertEquals(WopError.Category.configuration, e1.category());
        assertThrows(WopError.class, () -> client.buildRequest("POST", " ", body, SecurityLevel.L0));
        assertThrows(WopError.class, () -> client.buildRequest("POST", "/p", body, null));
        assertThrows(WopError.class, () -> client.buildRequest("POST", "/p", null, SecurityLevel.L2));
        assertThrows(WopError.class, () -> client.buildRequest("POST", "/p", new byte[0], SecurityLevel.L2));
    }

    @Test
    void methodIsCaseInsensitive() {
        WopClient client = fixedClient(NONCE);
        RequestDraft draft = client.buildRequest("post", "/p", null, SecurityLevel.L0);
        assertEquals("POST", draft.method());
    }

    @Test
    void headersUnmodifiable() {
        WopClient client = fixedClient(NONCE);
        RequestDraft draft = client.buildRequest("GET", "/p", null, SecurityLevel.L0);
        assertThrows(UnsupportedOperationException.class,
                () -> draft.headers().put("x-evil", "1"));
    }

    @Test
    void requestIdPassesThroughUnsignedHeader() {
        // requestId 以 x-wop-request-id 透传，不入 signedHeaders
        WopClient client = fromConfigClient();
        byte[] body = Codec.utf8("{\"k\":1}");
        RequestDraft draft = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0,
                WopRequestOptions.builder().requestId("req-001").build());
        assertEquals("req-001", draft.headers().get("x-wop-request-id"));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(!sign.signedHeaders().contains("x-wop-request-id"));
        assertTrue(signatureVerifies(draft, sign, RSA_PUB));

        RequestDraft l2 = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L2,
                WopRequestOptions.builder().requestId("req-002").build());
        assertEquals("req-002", l2.headers().get("x-wop-request-id"));
        SignHeader.Parsed l2Sign = SignHeader.parse(l2.headers().get("x-wop-sign"));
        assertTrue(!l2Sign.signedHeaders().contains("x-wop-request-id"));
        assertTrue(signatureVerifies(l2, l2Sign, RSA_PUB));
    }

    @Test
    void requestIdDefaultsToGeneratedUuidAndTrimsExplicitValue() {
        WopClient client = fixedClient(NONCE);
        String generated = client.buildRequest("GET", "/p", null, SecurityLevel.L0)
                .headers().get("x-wop-request-id");
        assertNotNull(generated);
        assertTrue(generated.matches("[0-9a-f]{32}"));
        String generatedFromBlank = client.buildRequest("GET", "/p", null, SecurityLevel.L0,
                WopRequestOptions.builder().requestId("  ").build())
                .headers().get("x-wop-request-id");
        assertTrue(generatedFromBlank.matches("[0-9a-f]{32}"));
        assertNotEquals(generated, generatedFromBlank);
        assertEquals("req-001", client.buildRequest("GET", "/p", null, SecurityLevel.L0,
                WopRequestOptions.builder().requestId("  req-001  ").build())
                .headers().get("x-wop-request-id"));
    }

    @Test
    void outboundLogContainsFinalRequestIdValue() {
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(WopClient.class.getName());
        java.util.List<String> lines = new java.util.ArrayList<>();
        java.util.logging.Handler capture = new java.util.logging.Handler() {
            @Override public void publish(java.util.logging.LogRecord record) {
                lines.add(record.getMessage());
            }
            @Override public void flush() { }
            @Override public void close() { }
        };
        log.addHandler(capture);
        java.util.logging.Level old = log.getLevel();
        log.setLevel(java.util.logging.Level.INFO);
        try {
            fixedClient(NONCE, () -> "logreq001").buildRequest("GET", "/p", null, SecurityLevel.L0);
        } finally {
            log.removeHandler(capture);
            log.setLevel(old);
        }
        assertTrue(lines.stream().anyMatch(m -> m.contains("x-wop-request-id=logreq001")),
                "日志行必须含最终透传头值: " + lines);
    }

    @Test
    void requestIdRejectsControlCharacters() {
        WopClient client = fromConfigClient();
        WopError e1 = assertThrows(WopError.class,
                () -> client.buildRequest("GET", "/p", null, SecurityLevel.L0,
                        WopRequestOptions.builder().requestId("bad\r\nx-inject: 1").build()));
        assertEquals(WopError.Category.configuration, e1.category());
        assertThrows(WopError.class,
                () -> client.buildRequest("GET", "/p", null, SecurityLevel.L0,
                        WopRequestOptions.builder().requestId("bad\u0000id").build()));
        assertThrows(WopError.class,
                () -> client.buildRequest("GET", "/p", null, SecurityLevel.L0,
                        WopRequestOptions.builder().requestId("bad\u007fid").build()));
    }

    @Test
    void requestIdLengthLimit() {
        WopClient client = fixedClient(NONCE);
        String len128 = repeat('a', 128);
        RequestDraft ok = client.buildRequest("GET", "/p", null, SecurityLevel.L0,
                WopRequestOptions.builder().requestId(len128).build());
        assertEquals(len128, ok.headers().get("x-wop-request-id"));

        assertThrows(WopError.class,
                () -> WopRequestOptions.builder().requestId(repeat('a', 129)).build());
    }

    private static String repeat(char c, int count) {
        char[] arr = new char[count];
        java.util.Arrays.fill(arr, c);
        return new String(arr);
    }

    @Test
    void requestIdOnlyDoesNotRequireSdkConfig() {
        WopClient builderClient = WopClient.builder()
                .appKey("app_001").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build();
        // 直接用 builder client（无 sdkConfig）发 requestId 透传，不会抛"需要 fromConfig"
        RequestDraft draft = builderClient.buildRequest("GET", "/p", null, SecurityLevel.L0,
                WopRequestOptions.builder().requestId("req-only").build());
        assertEquals("req-only", draft.headers().get("x-wop-request-id"));
    }

    static boolean signatureVerifies(RequestDraft draft, SignHeader.Parsed sign, String publicKeyB64) {
        return signatureVerifies(draft, sign, com.wanlianyida.wop.crypto.KeyCodec.parsePublicKey(
                publicKeyB64, AlgorithmSuite.parse(sign.securityReq())));
    }

    static boolean signatureVerifies(RequestDraft draft, SignHeader.Parsed sign, PublicKey publicKey) {
        Map<String, String> signed = new TreeMap<>();
        Map<String, String> lower = new LinkedHashMap<>();
        draft.headers().forEach((k, v) -> lower.put(k.toLowerCase(java.util.Locale.ROOT), v));
        for (String name : sign.signedHeaders()) {
            signed.put(name, lower.get(name));
        }
        String canonical = CanonicalRequest.build(
                sign.protocolVersion() + "/" + sign.expiredSeconds(),
                draft.method(), draft.path(), "", CanonicalRequest.canonicalHeaders(signed));
        AlgorithmSuite suite = AlgorithmSuite.parse(sign.securityReq());
        return suite.signature().verify(Codec.utf8(canonical),
                Codec.b64UrlDecode(sign.signature()), publicKey,
                Codec.utf8(draft.headers().get("x-wop-appkey")));
    }
}
