package com.wanlianyida.wop;

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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WopClient.buildRequest 出向：L0/L2 信封、I1 digest 入签、D2 缺席语义、
 * F9 nonce/timestamp、确定性（注入 clock/nonce 后字节可重放）。
 */
class WopClientBuildRequestTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String RSA4096_PUB = TestVectors.keys("rsa4096").path("publicSpkiB64").asText();

    /** 固定 clock/nonce 的测试客户端（可重放生成断言）。 */
    private static WopClient fixedClient(Supplier<String> nonce) {
        LongSupplier clock = () -> 1_758_900_000_000L;
        return testClient("WOP-RSA3072-SHA256", nonce, clock);
    }

    static WopClient testClient(String suite, Supplier<String> nonce, LongSupplier clock) {
        return new WopClient(new WopClient.Config(
                "app_001", AlgorithmSuite.parse(suite),
                RSA_PRIV, RSA_PUB, 1800), clock, nonce);
    }

    private static final Supplier<String> NONCE = () -> "fixed00000000000000000000000000a";

    @Test
    void builderRequiresMandatoryFields() {
        // appKey / suite / 双钥缺一不可，fail-fast 于 build()
        assertThrows(WopSdkException.class, () -> WopClient.builder().build());
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey("a").build());
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256").build());
        WopClient.Builder partial = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV);
        assertThrows(WopSdkException.class, partial::build);
        // 非法套件
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey("a")
                .suite("WOP-RSA3072-SM3").merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build());
        // 密钥与套件长度不符
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey("a")
                .suite("WOP-RSA4096-SHA256").merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build());
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey("a")
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
        // D2：无 body → digest 头缺席
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
    }

    @Test
    void l0PostWithBodySignsDigest() {
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{\"orderId\":\"W1\"}");
        RequestDraft draft = client.buildRequest("POST", "/gateway/order/create", body, SecurityLevel.L0);

        // D2/I1：digest 存在、入签、等于 SHA-256(wire body)
        String digest = draft.headers().get("x-wop-content-digest");
        String expected = "sha-256 " + Codec.hexLower(
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").digest().digest(body));
        assertEquals(expected, digest);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-content-digest"));
        assertArrayEquals(body, draft.wireBody());

        // 签名可用商户公钥验证（网关侧行为）：重建 canonical
        assertTrue(signatureVerifies(draft, sign, RSA_PUB));
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

        // digest 对密文载体（D2：摘要对象 = 线上原始报文字节）
        String digest = draft.headers().get("x-wop-content-digest");
        assertEquals("sha-256 " + Codec.hexLower(
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").digest().digest(draft.wireBody())), digest);

        // x-wop-encrypt 存在且入签（I1 同级规则）
        String encryptHeader = draft.headers().get("x-wop-encrypt");
        assertTrue(encryptHeader.startsWith("L2;dek="));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-encrypt"));

        // 平台私钥解包 DEK → AES-256-GCM → 解密 wire 得原文（请求方向角色对调自证）
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
        // 平台私钥（同对密钥自证）解包 C1C3C2 → SM4-GCM dek
        PrivateKey priv = com.wanlianyida.wop.crypto.KeyCodec.parsePrivateKey(
                TestVectors.keys("sm2").path("privateDB64").asText(), AlgorithmSuite.parse("WOP-SM2-SM3"));
        byte[] dekPlain = AlgorithmSuite.parse("WOP-SM2-SM3").keyEncrypt()
                .decrypt(Codec.b64UrlDecode(parsed.dek()), priv);
        DekPayload dek = DekPayload.decode(new String(dekPlain, StandardCharsets.UTF_8));
        assertEquals("SM4-GCM", dek.alg());
        assertEquals(16, dek.key().length);
        // digest 标签 sm3
        assertTrue(draft.headers().get("x-wop-content-digest").startsWith("sm3 "));
        // 解密回原文
        String wire = new String(draft.wireBody(), StandardCharsets.UTF_8);
        byte[] cipher = Codec.b64UrlDecode(wire.substring(14, wire.length() - 2));
        assertArrayEquals(body, AlgorithmSuite.parse("WOP-SM2-SM3").messageEncrypt()
                .decrypt(cipher, dek.iv(), dek.key()));
        // 签名验证（SM2，86 字符 b64url）
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(86, sign.signature().length());
        PublicKey merchantPub = com.wanlianyida.wop.crypto.KeyCodec.parsePublicKey(
                TestVectors.keys("sm2").path("publicPointB64").asText(), AlgorithmSuite.parse("WOP-SM2-SM3"));
        assertTrue(signatureVerifies(draft, sign, merchantPub));
    }

    @Test
    void deterministicReplayWithFixedClockAndNonce() {
        // spec §2：同输入同输出（除 CSPRNG IV/nonce）——L0 注入固定 ts/nonce 字节级一致
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{\"k\":1}");
        RequestDraft a = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0);
        RequestDraft b = client.buildRequest("POST", "/gateway/x", body, SecurityLevel.L0);
        assertEquals(a.headers(), b.headers());
        assertArrayEquals(a.wireBody(), b.wireBody());

        // L2：DEK/IV 为 CSPRNG，headers 除 digest/encrypt 外一致
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
        // 时间戳为 13 位毫秒
        assertTrue(a.headers().get("x-wop-timestamp").matches("\\d{13}"));
    }

    @Test
    void rejectsInvalidBuildRequestArguments() {
        WopClient client = fixedClient(NONCE);
        byte[] body = Codec.utf8("{}");
        assertThrows(WopSdkException.class, () -> client.buildRequest(" ", "/p", body, SecurityLevel.L0));
        assertThrows(WopSdkException.class, () -> client.buildRequest("POST", " ", body, SecurityLevel.L0));
        assertThrows(WopSdkException.class, () -> client.buildRequest("POST", "/p", body, null));
        // L2 需要非空 body
        assertThrows(WopSdkException.class, () -> client.buildRequest("POST", "/p", null, SecurityLevel.L2));
        assertThrows(WopSdkException.class, () -> client.buildRequest("POST", "/p", new byte[0], SecurityLevel.L2));
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

    /** 网关侧等价验证：按 signedHeaders 从 draft.headers 重建 canonical 并用商户公钥验签。 */
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
                Codec.b64UrlDecode(sign.signature()), publicKey);
    }
}
