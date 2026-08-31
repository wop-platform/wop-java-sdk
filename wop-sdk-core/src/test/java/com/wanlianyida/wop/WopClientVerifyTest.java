package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.CanonicalRequest;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.ContentDigest;
import com.wanlianyida.wop.crypto.DekPayload;
import com.wanlianyida.wop.crypto.EncryptedEnvelope;
import com.wanlianyida.wop.crypto.EncryptHeader;
import com.wanlianyida.wop.crypto.KeyCodec;
import com.wanlianyida.wop.crypto.SignHeader;
import com.wanlianyida.wop.crypto.TestVectors;
import com.wanlianyida.wop.crypto.strategies.CipherResult;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F6 校验顺序 + I7 模糊化 + D2/I1/I5 负向量：verifyResponse / verifyCallback。
 * 平台侧响应由 PlatformRig 按协议拼装（平台私钥加签、商户公钥包 DEK）。
 * spec:D14：平台侧验签/签名 userId = 协议固定值（与入向验签一致；出向由商户显式传 appKey）。
 */
class WopClientVerifyTest {

    private static final String MERCHANT_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String MERCHANT_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String PLATFORM_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String PLATFORM_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static final AlgorithmSuite RSA = AlgorithmSuite.parse("WOP-RSA3072-SHA256");

    /** 商户客户端（merchant=rsa3072 对，platform=rsa4096 公钥）。 */
    private final WopClient client = WopClient.builder()
            .appKey("app_001").suite("WOP-RSA3072-SHA256")
            .merchantPrivateKey(MERCHANT_PRIV).platformPublicKey(PLATFORM_PUB)
            .build();

    /** 平台响应快照。 */
    record PlatformResponse(Map<String, String> headers, byte[] wire) {
    }

    /** 平台侧响应拼装（镜像 SignFilter.post + CryptoFilter.post 出站行为）。 */
    static final class PlatformRig {

        final String securityReq;
        final String platformPrivB64;
        final String merchantPubB64;

        PlatformRig(String securityReq, String platformPrivB64, String merchantPubB64) {
            this.securityReq = securityReq;
            this.platformPrivB64 = platformPrivB64;
            this.merchantPubB64 = merchantPubB64;
        }

        /** 拼装响应：L2 时对 plain 全文加密，wire 为密文信封；出站签名头完整。 */
        PlatformResponse respond(String path, byte[] plain, boolean l2) {
            AlgorithmSuite suite = AlgorithmSuite.parse(securityReq);
            PrivateKey platformPriv = KeyCodec.parsePrivateKey(platformPrivB64, suite);
            PublicKey merchantPub = KeyCodec.parsePublicKey(merchantPubB64, suite);

            byte[] wire = plain;
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("x-wop-timestamp", "1758900000000");
            headers.put("x-wop-nonce", "platformnonce0000000000000000001");

            if (l2) {
                byte[] dek = new byte[suite.messageEncrypt().keyLength()];
                new java.security.SecureRandom().nextBytes(dek);
                CipherResult result = suite.messageEncrypt().encrypt(plain, dek);
                wire = EncryptedEnvelope.wrap(Codec.b64UrlEncode(result.cipher()));
                String payload = DekPayload.encode(new DekPayload(suite.expectedDekAlg(), dek, result.iv()));
                byte[] wrapped = suite.keyEncrypt().encrypt(Codec.utf8(payload), merchantPub);
                headers.put("x-wop-encrypt", EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
            }
            if (wire != null && wire.length > 0) {
                headers.put("x-wop-content-digest", ContentDigest.build(suite, wire));
            }

            // 响应侧 signedHeaders：digest（有 body）/encrypt（L2）/nonce/timestamp，ASCII 升序（不含 appkey）
            List<String> signed = new ArrayList<>();
            if (headers.containsKey("x-wop-content-digest")) {
                signed.add("x-wop-content-digest");
            }
            if (headers.containsKey("x-wop-encrypt")) {
                signed.add("x-wop-encrypt");
            }
            signed.add("x-wop-nonce");
            signed.add("x-wop-timestamp");
            signed.sort(String::compareTo);
            signHeaders(headers, signed, path, suite, platformPriv);
            return new PlatformResponse(headers, wire);
        }

        private static void signHeaders(Map<String, String> headers, List<String> signed, String path,
                                        AlgorithmSuite suite, PrivateKey platformPriv) {
            Map<String, String> sub = new TreeMap<>();
            signed.forEach(n -> sub.put(n, headers.get(n)));
            String canonical = CanonicalRequest.build("v1/1800", "POST", path, "",
                    CanonicalRequest.canonicalHeaders(sub));
            byte[] sig = suite.signature().sign(Codec.utf8(canonical), platformPriv, Codec.utf8("1234567812345678"));
            headers.put("x-wop-sign", SignHeader.build(suite.securityReq(), 1800, signed,
                    Codec.b64UrlEncode(sig)));
        }
    }

    private static final PlatformRig RSA_RIG = new PlatformRig("WOP-RSA3072-SHA256", PLATFORM_PRIV, MERCHANT_PUB);

    // ==================== 正向：L0 / L2 / 回调 / Transport 重载 ====================

    @Test
    void verifyResponseL0Ok() {
        byte[] body = Codec.utf8("{\"code\":\"SUCCESS\"}");
        PlatformResponse resp = RSA_RIG.respond("/gateway/order/create", body, false);
        VerifyResult result = client.verifyResponse(resp.headers(), body, "/gateway/order/create");
        assertTrue(result.ok());
        assertNull(result.reason());
        assertArrayEquals(body, result.plaintext());
    }

    @Test
    void verifyResponseL2Ok() {
        byte[] plain = Codec.utf8("{\"data\":\"secret\"}");
        PlatformResponse resp = RSA_RIG.respond("/gateway/pay", plain, true);
        VerifyResult result = client.verifyResponse(resp.headers(), resp.wire(), "/gateway/pay");
        assertTrue(result.ok(), () -> result.toString());
        assertArrayEquals(plain, result.plaintext());
    }

    @Test
    void verifyCallbackL2Ok() {
        byte[] plain = Codec.utf8("{\"eventId\":\"e1\"}");
        PlatformResponse resp = RSA_RIG.respond("/merchant/callback", plain, true);
        VerifyResult result = client.verifyCallback(resp.headers(), resp.wire(), "/merchant/callback");
        assertTrue(result.ok(), () -> result.toString());
        assertEquals("{\"eventId\":\"e1\"}", result.plaintextAsUtf8());
    }

    @Test
    void verifyViaTransportResponseOverload() {
        byte[] plain = Codec.utf8("ok");
        PlatformResponse resp = RSA_RIG.respond("/gateway/x", plain, false);
        RequestDraft draft = client.buildRequest("POST", "/gateway/x", Codec.utf8("{}"), SecurityLevel.L0);
        TransportResponse transport = new TransportResponse(200, resp.headers(), plain);
        assertTrue(client.verifyResponse(transport, draft).ok());
    }

    // ==================== 验签类（I7 模糊） ====================

    @Test
    void tamperedSignatureFailsVaguely() {
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        SignHeader.Parsed parsed = SignHeader.parse(resp.headers().get("x-wop-sign"));
        byte[] sig = Codec.b64UrlDecode(parsed.signature());
        sig[5] ^= 0x01;
        resp.headers().put("x-wop-sign", SignHeader.build("WOP-RSA3072-SHA256", 1800,
                parsed.signedHeaders(), Codec.b64UrlEncode(sig)));
        VerifyResult result = client.verifyResponse(resp.headers(), body, "/p");
        assertFalse(result.ok());
        assertEquals(VerifyResult.Reason.SIGNATURE_FAILED, result.reason());
        assertEquals("签名验证失败", result.message());
    }

    @Test
    void signatureWithPaddingCharFailsExplicitly() {
        // F7 负向量 + interop n06 裁决：带 '=' 的 base64url 签名是公开结构知识，
        // 协议类明确拒绝（解析层格式错误），非验签模糊
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        SignHeader.Parsed parsed = SignHeader.parse(resp.headers().get("x-wop-sign"));
        resp.headers().put("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/" + String.join(";", parsed.signedHeaders())
                + "/" + parsed.signature() + "=");
        VerifyResult result = client.verifyResponse(resp.headers(), body, "/p");
        assertEquals(VerifyResult.Reason.INVALID_SIGN_HEADER, result.reason());
        assertTrue(result.message().contains("格式错误") && result.detail() != null, result.message());
    }

    @Test
    void crossFamilySignatureLengthFailsExplicitly() {
        // RSA 套件 + 86 字符（64B，SM2 形态）签名 → 定长前置校验，协议类明确拒绝（interop n07/n08 同族）
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        SignHeader.Parsed parsed = SignHeader.parse(resp.headers().get("x-wop-sign"));
        resp.headers().put("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/" + String.join(";", parsed.signedHeaders())
                + "/Si7Uw5eZm0Kii3BuIRLXwMGGOxkwFria8ypcVYXnReV376EVgV0TOkQfm21NUnJZNGM-fV0d0fMF23B0Bm3TFw");
        VerifyResult result = client.verifyResponse(resp.headers(), body, "/p");
        assertEquals(VerifyResult.Reason.INVALID_SIGN_HEADER, result.reason());
        assertTrue(result.message().contains("定长"));
    }

    @Test
    void missingSignHeaderExplicit() {
        assertEquals(VerifyResult.Reason.MISSING_SIGN_HEADER,
                client.verifyResponse(Map.of(), Codec.utf8("{}"), "/p").reason());
    }

    @Test
    void malformedSignHeaderExplicit() {
        VerifyResult result = client.verifyResponse(Map.of("x-wop-sign", "garbage"),
                Codec.utf8("{}"), "/p");
        assertEquals(VerifyResult.Reason.INVALID_SIGN_HEADER, result.reason());
        assertTrue(result.message().contains("格式错误"));
    }

    @Test
    void unsupportedSuiteInResponseExplicit() {
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        SignHeader.Parsed parsed = SignHeader.parse(resp.headers().get("x-wop-sign"));
        resp.headers().put("x-wop-sign", "WOP-SM2-SHA256 v1/1800/" + String.join(";", parsed.signedHeaders())
                + "/" + parsed.signature());
        assertEquals(VerifyResult.Reason.UNSUPPORTED_SUITE,
                client.verifyResponse(resp.headers(), body, "/p").reason());
    }

    // ==================== 完整性类（D2/I1，明确） ====================

    @Test
    void digestMismatchExplicit() {
        // 签名有效但 body 被换 → 摘要不匹配（明确）
        byte[] body = Codec.utf8("{\"v\":1}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        VerifyResult result = client.verifyResponse(resp.headers(), Codec.utf8("{\"v\":2}"), "/p");
        assertEquals(VerifyResult.Reason.DIGEST_MISMATCH, result.reason());
        assertEquals("摘要不匹配", result.message());
    }

    @Test
    void bodyWithoutDigestHeaderRejected() {
        // D2：有 body 必传（重签去掉 digest 头与声明后仍必须拒）
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        resp.headers().remove("x-wop-content-digest");
        reSignWith(resp.headers(), "/p", List.of("x-wop-nonce", "x-wop-timestamp"));
        assertEquals(VerifyResult.Reason.MISSING_DIGEST_HEADER,
                client.verifyResponse(resp.headers(), body, "/p").reason());
    }

    @Test
    void digestPresentWithoutBodyRejected() {
        // D2：无 body → digest 头必须缺席
        PlatformResponse resp = RSA_RIG.respond("/p", Codec.utf8("x"), false);
        assertEquals(VerifyResult.Reason.INVALID_DIGEST_HEADER,
                client.verifyResponse(resp.headers(), new byte[0], "/p").reason());
    }

    @Test
    void digestHeaderFormatViolationsExplicit() {
        String[] bad = {
                "sha-256  23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf",  // 双空格
                "sha-256 23592263765CF506D07CC8614C09067E6DE38E64C53E5B672C022532D01737CF",    // 大写 hex
                "sha-256 3592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf",     // 63 字符
                "sm3 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf",        // 跨族
        };
        byte[] body = Codec.utf8("{}");
        for (String badDigest : bad) {
            PlatformResponse resp = RSA_RIG.respond("/p", body, false);
            resp.headers().put("x-wop-content-digest", badDigest);
            reSignWith(resp.headers(), "/p", List.of(
                    "x-wop-content-digest", "x-wop-nonce", "x-wop-timestamp"));
            VerifyResult result = client.verifyResponse(resp.headers(), body, "/p");
            assertEquals(VerifyResult.Reason.INVALID_DIGEST_HEADER, result.reason(), badDigest);
        }
    }

    @Test
    void digestNotInSignedHeadersRejected() {
        // I1 负向量：digest 头存在但未入签 → body 退回无保护，必须拒
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        reSignWith(resp.headers(), "/p", List.of("x-wop-nonce", "x-wop-timestamp"));
        assertEquals(VerifyResult.Reason.MISSING_SIGNED_HEADER,
                client.verifyResponse(resp.headers(), body, "/p").reason());
    }

    @Test
    void encryptNotInSignedHeadersRejected() {
        byte[] plain = Codec.utf8("secret");
        PlatformResponse resp = RSA_RIG.respond("/p", plain, true);
        reSignWith(resp.headers(), "/p", List.of(
                "x-wop-content-digest", "x-wop-nonce", "x-wop-timestamp"));
        assertEquals(VerifyResult.Reason.MISSING_SIGNED_HEADER,
                client.verifyResponse(resp.headers(), resp.wire(), "/p").reason());
    }

    @Test
    void signedHeaderMissingInRequestRejected() {
        byte[] body = Codec.utf8("{}");
        PlatformResponse resp = RSA_RIG.respond("/p", body, false);
        resp.headers().remove("x-wop-nonce");
        assertEquals(VerifyResult.Reason.MISSING_HEADER,
                client.verifyResponse(resp.headers(), body, "/p").reason());
    }

    @Test
    void rsa4096SuiteResponseRoundtrip() {
        String k4096Priv = TestVectors.keys("rsa4096").path("privatePkcs8B64").asText();
        String k4096Pub = TestVectors.keys("rsa4096").path("publicSpkiB64").asText();
        WopClient client4096 = WopClient.builder().appKey("app_4096").suite("WOP-RSA4096-SHA256")
                .merchantPrivateKey(k4096Priv).platformPublicKey(k4096Pub).build();
        PlatformRig rig = new PlatformRig("WOP-RSA4096-SHA256", k4096Priv, k4096Pub);
        byte[] plain = Codec.utf8("{\"suite\":4096}");
        PlatformResponse resp = rig.respond("/p4096", plain, true);
        VerifyResult result = client4096.verifyResponse(resp.headers(), resp.wire(), "/p4096");
        assertTrue(result.ok(), () -> result.toString());
        assertArrayEquals(plain, result.plaintext());
        assertEquals(683, SignHeader.parse(resp.headers().get("x-wop-sign")).signature().length());
    }

    @Test
    void l2TamperedCiphertextFailsVaguely() {
        byte[] plain = Codec.utf8("plain");
        PlatformResponse resp = RSA_RIG.respond("/p", plain, true);
        byte[] wire = resp.wire().clone();
        // 随机 DEK 下尾段 base64url 字符不定，^0x01 有 ~9% 概率翻出字母表外（A→@ 等），
        // 落点漂移到信封解码失败（INVALID_ENCRYPTED_BODY）而非解密失败。改为替换成
        // 确定的另一合法字母表字符（'B'↔'C'），保证直达 AES-GCM 解密 → 确定性 DECRYPT_FAILED。
        wire[wire.length - 3] = wire[wire.length - 3] == 'B' ? (byte) 'C' : (byte) 'B';
        resp.headers().put("x-wop-content-digest", ContentDigest.build(RSA, wire));
        reSignWith(resp.headers(), "/p", List.of(
                "x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"));
        VerifyResult result = client.verifyResponse(resp.headers(), wire, "/p");
        assertFalse(result.ok());
        assertEquals(VerifyResult.Reason.DECRYPT_FAILED, result.reason());
        assertEquals("解密失败", result.message());
    }

    @Test
    void l2GarbageDekFailsVaguely() {
        byte[] plain = Codec.utf8("plain");
        PlatformResponse resp = RSA_RIG.respond("/p", plain, true);
        resp.headers().put("x-wop-encrypt", "L2;dek=AAAA");
        reSignWith(resp.headers(), "/p", List.of(
                "x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"));
        assertEquals(VerifyResult.Reason.DECRYPT_FAILED,
                client.verifyResponse(resp.headers(), resp.wire(), "/p").reason());
    }

    @Test
    void l2DekAlgMismatchExplicit() {
        byte[] plain = Codec.utf8("plain");
        PlatformResponse resp = RSA_RIG.respond("/p", plain, true);
        byte[] sm4Key = Codec.b64UrlDecode(TestVectors.input("sm4KeyB64u"));
        byte[] sm4Iv = Codec.b64UrlDecode(TestVectors.input("sm4IvB64u"));
        String payload = DekPayload.encode(new DekPayload("SM4-GCM", sm4Key, sm4Iv));
        PublicKey merchantPub = KeyCodec.parsePublicKey(MERCHANT_PUB, RSA);
        byte[] wrapped = RSA.keyEncrypt().encrypt(Codec.utf8(payload), merchantPub);
        resp.headers().put("x-wop-encrypt", EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
        reSignWith(resp.headers(), "/p", List.of(
                "x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"));
        VerifyResult result = client.verifyResponse(resp.headers(), resp.wire(), "/p");
        assertEquals(VerifyResult.Reason.DEK_ALG_MISMATCH, result.reason());
        assertTrue(result.message().contains("SM4-GCM"));
    }

    @Test
    void l2InvalidEnvelopeExplicit() {
        PlatformResponse resp = RSA_RIG.respond("/p", Codec.utf8("x"), true);
        byte[] notEnvelope = Codec.utf8("{\"other\":1}");
        resp.headers().put("x-wop-content-digest", ContentDigest.build(RSA, notEnvelope));
        reSignWith(resp.headers(), "/p", List.of(
                "x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"));
        assertEquals(VerifyResult.Reason.INVALID_ENCRYPTED_BODY,
                client.verifyResponse(resp.headers(), notEnvelope, "/p").reason());
    }

    @Test
    void l2InvalidEncryptHeaderExplicit() {
        PlatformResponse resp = RSA_RIG.respond("/p", Codec.utf8("x"), true);
        resp.headers().put("x-wop-encrypt", "L9;dek=abc");
        reSignWith(resp.headers(), "/p", List.of(
                "x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"));
        assertEquals(VerifyResult.Reason.INVALID_ENCRYPT_HEADER,
                client.verifyResponse(resp.headers(), resp.wire(), "/p").reason());
    }

    @Test
    void l2EmptyBodyRejected() {
        PlatformResponse resp = RSA_RIG.respond("/p", Codec.utf8("x"), true);
        assertEquals(VerifyResult.Reason.INVALID_DIGEST_HEADER,
                client.verifyResponse(resp.headers(), new byte[0], "/p").reason());
    }

    @Test
    void sm2SuiteResponseRoundtrip() {
        String sm2Priv = TestVectors.keys("sm2").path("privateDB64").asText();
        String sm2Pub = TestVectors.keys("sm2").path("publicPointB64").asText();
        WopClient sm2Client = WopClient.builder().appKey("app_sm2").suite("WOP-SM2-SM3")
                .merchantPrivateKey(sm2Priv).platformPublicKey(sm2Pub).build();
        PlatformRig rig = new PlatformRig("WOP-SM2-SM3", sm2Priv, sm2Pub);
        byte[] plain = Codec.utf8("{\"sm\":true}");
        PlatformResponse resp = rig.respond("/cb", plain, true);
        VerifyResult result = sm2Client.verifyCallback(resp.headers(), resp.wire(), "/cb");
        assertTrue(result.ok(), () -> result.toString());
        assertArrayEquals(plain, result.plaintext());
        SignHeader.Parsed parsed = SignHeader.parse(resp.headers().get("x-wop-sign"));
        byte[] sig = Codec.b64UrlDecode(parsed.signature());
        resp.headers().put("x-wop-sign", SignHeader.build("WOP-SM2-SM3", 1800, parsed.signedHeaders(),
                Codec.b64UrlEncode(java.util.Arrays.copyOfRange(sig, 0, 63))));
        assertEquals(VerifyResult.Reason.INVALID_SIGN_HEADER,
                sm2Client.verifyCallback(resp.headers(), resp.wire(), "/cb").reason());
    }

    /** I7 韧性：验签策略内部抛 RuntimeException（而非返回 false）时不得外泄异常，须模糊化为 SIGNATURE_FAILED。
     *  注入：合法构建后反射替换 platformPublicKey 为 RSA 公钥，SM2 曲线守卫（toPublicParams）抛
     *  IllegalArgumentException → 策略包装 CryptoException → verifyInbound catch。 */
    @Test
    void signatureStrategyRuntimeExceptionFailsVaguely() throws Exception {
        String sm2Priv = TestVectors.keys("sm2").path("privateDB64").asText();
        String sm2Pub = TestVectors.keys("sm2").path("publicPointB64").asText();
        WopClient sm2Client = WopClient.builder().appKey("app_sm2").suite("WOP-SM2-SM3")
                .merchantPrivateKey(sm2Priv).platformPublicKey(sm2Pub).build();
        PlatformRig rig = new PlatformRig("WOP-SM2-SM3", sm2Priv, sm2Pub);
        byte[] plain = Codec.utf8("{\"sm\":true}");
        PlatformResponse resp = rig.respond("/cb", plain, false);
        java.lang.reflect.Field keyField = WopClient.class.getDeclaredField("platformPublicKey");
        keyField.setAccessible(true);
        keyField.set(sm2Client, KeyCodec.parsePublicKey(
                TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA));
        VerifyResult result = sm2Client.verifyCallback(resp.headers(), resp.wire(), "/cb");
        assertFalse(result.ok());
        assertEquals(VerifyResult.Reason.SIGNATURE_FAILED, result.reason());
        assertNull(result.detail(), "策略内部异常不应泄露细节（I7）");
    }

    private void reSignWith(Map<String, String> headers, String path, List<String> signedNames) {
        PrivateKey platformPriv = KeyCodec.parsePrivateKey(PLATFORM_PRIV, RSA);
        Map<String, String> sub = new TreeMap<>();
        signedNames.forEach(n -> sub.put(n, headers.get(n)));
        String canonical = CanonicalRequest.build("v1/1800", "POST", path, "",
                CanonicalRequest.canonicalHeaders(sub));
        // spec:D14：平台侧重签 userId 与装配一致
        byte[] sig = RSA.signature().sign(Codec.utf8(canonical), platformPriv, Codec.utf8("1234567812345678"));
        headers.put("x-wop-sign", SignHeader.build("WOP-RSA3072-SHA256", 1800, signedNames,
                Codec.b64UrlEncode(sig)));
    }
}
