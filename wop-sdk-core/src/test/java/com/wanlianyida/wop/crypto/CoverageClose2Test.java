package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.TestText;
import com.wanlianyida.wop.VerifyResult;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.strategies.Aes256GcmStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2Support;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖闭合第二批：分支组合补全。
 */
class CoverageClose2Test {

    private static final AlgorithmSuite RSA = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    @Test
    void isLowerHex64CharClassCombinations() {
        assertTrue(Codec.isLowerHex64(TestText.repeat("0123456789abcdef", 4)));
        assertFalse(Codec.isLowerHex64(TestText.repeat(":", 64)));   // '9' 之后
        assertFalse(Codec.isLowerHex64(TestText.repeat("/", 64)));   // '9' 与 'a' 之间
        assertFalse(Codec.isLowerHex64(TestText.repeat("`", 64)));   // 'f' 之后
        assertFalse(Codec.isLowerHex64(TestText.repeat("@", 64)));   // 'Z' 与 'a' 之间
    }

    @Test
    void b64UrlCharClassesAllCovered() {
        assertArrayEquals(new byte[]{(byte) 0xFB, (byte) 0xFF, (byte) 0xBF}, Codec.b64UrlDecode("-_-_"));
        assertEquals("-_8", Codec.b64UrlEncode(new byte[]{(byte) 0xFB, (byte) 0xFF}));
    }

    @Test
    void aesGcmIvLengthGuard() {
        byte[] key = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        byte[] plain = Codec.utf8("x");
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.decrypt(plain, null, key));
        assertThrows(CryptoException.class,
                () -> Aes256GcmStrategy.INSTANCE.decrypt(plain, new byte[13], key));
    }

    @Test
    void sm2PointAndScalarEdgeBranches() {
        byte[] wrongPrefix = new byte[65];
        wrongPrefix[0] = 0x02;
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(wrongPrefix));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireValidD(BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireValidD(BigInteger.valueOf(2).pow(300)));
        Sm2Support.requireValidD(BigInteger.ONE);
    }

    @Test
    void sm2SignWithNullUserIdRejected() {
        // spec:D14：userId=null → 显式拒绝（无默认回退），sign/verify 双路径覆盖 withId null 分支
        byte[] msg = Codec.utf8("x");
        PrivateKey priv = KeyCodec.parsePrivateKey(
                TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        PublicKey pub = KeyCodec.parsePublicKey(
                TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        assertThrows(CryptoException.class, () -> Sm2SignatureStrategy.INSTANCE.sign(msg, priv, null));
        assertThrows(CryptoException.class, () -> Sm2SignatureStrategy.INSTANCE.verify(msg, new byte[64], pub, null));
    }

    @Test
    void signHeaderMiddleEmptySegmentRejected() {
        assertThrows(WopError.class,
                () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a;;b/c2ln"));
        assertThrows(WopError.class,
                () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/;a/c2ln"));
    }

    @Test
    void dekPayloadRecordMethods() {
        byte[] key = new byte[]{1};
        byte[] iv = new byte[]{2};
        DekPayload a = new DekPayload("AES-256-GCM", key, iv);
        DekPayload b = new DekPayload("AES-256-GCM", key, iv);   // record 数组字段浅比较：同引用相等
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals("AES-256-GCM", a.alg());
        assertArrayEquals(key, a.key());
        assertArrayEquals(iv, a.iv());
        assertFalse(a.equals(null));
    }

    @Test
    void verifyResultOkFalseReasonNull() {
        assertNull(new VerifyResult(false, null, null, null).message());
    }

    @Test
    void canonicalRequestFullNullCombination() {
        assertEquals("\n\n\n\n", CanonicalRequest.build(null, null, null, null, null));
        assertEquals("\nGET\n/p\n\n", CanonicalRequest.build(null, "get", "/p", null, null));
    }

    @Test
    void verifyResponseNullHeadersAndBodyless() {
        com.wanlianyida.wop.WopClient client = com.wanlianyida.wop.WopClient.builder()
                .appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText())
                .platformPublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText())
                .build();
        assertEquals(VerifyResult.Reason.MISSING_SIGN_HEADER,
                client.verifyResponse(null, Codec.utf8("x"), "/p").reason());

        // 无 body 响应（GET 语义）：digest 缺席 + 完整签名 → ok
        PrivateKey platformPriv = KeyCodec.parsePrivateKey(
                TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-wop-timestamp", "1758900000000");
        headers.put("x-wop-nonce", "n1");
        Map<String, String> sub = new java.util.TreeMap<>();
        sub.put("x-wop-nonce", "n1");
        sub.put("x-wop-timestamp", "1758900000000");
        String canonical = CanonicalRequest.build("v1/1800", "POST", "/p", "",
                CanonicalRequest.canonicalHeaders(sub));
        headers.put("x-wop-sign", SignHeader.build("WOP-RSA3072-SHA256", 1800,
                Arrays.asList("x-wop-nonce", "x-wop-timestamp"),
                Codec.b64UrlEncode(RSA.signature().sign(Codec.utf8(canonical), platformPriv,
                        Codec.utf8("1234567812345678")))));
        VerifyResult result = client.verifyResponse(headers, null, "/p");
        assertTrue(result.ok(), () -> result.toString());
        assertNull(result.plaintext());
        assertTrue(client.verifyResponse(headers, new byte[0], "/p").ok());
    }

    @Test
    void l2UnwrappedDekPayloadMalformedExplicit() {
        // 解包成功但载荷非 alg$key$iv → 明确拒绝（公开协议知识，密文内容无关紧要）
        com.wanlianyida.wop.WopClient client = com.wanlianyida.wop.WopClient.builder()
                .appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText())
                .platformPublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText())
                .build();
        PublicKey merchantPub = KeyCodec.parsePublicKey(
                TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA);
        byte[] wrapped = RSA.keyEncrypt().encrypt(Codec.utf8("garbage-not-a-dek"), merchantPub);
        PrivateKey platformPriv = KeyCodec.parsePrivateKey(
                TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA);

        byte[] dek = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        byte[] wire = EncryptedEnvelope.wrap(Codec.b64UrlEncode(
                Aes256GcmStrategy.INSTANCE.encrypt(Codec.utf8("payload"), dek).cipher()));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("x-wop-timestamp", "1758900000000");
        headers.put("x-wop-nonce", "n1");
        headers.put("x-wop-encrypt", EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
        headers.put("x-wop-content-digest", ContentDigest.build(RSA, wire));
        Map<String, String> sub = new java.util.TreeMap<>();
        sub.put("x-wop-content-digest", headers.get("x-wop-content-digest"));
        sub.put("x-wop-encrypt", headers.get("x-wop-encrypt"));
        sub.put("x-wop-nonce", "n1");
        sub.put("x-wop-timestamp", "1758900000000");
        String canonical = CanonicalRequest.build("v1/1800", "POST", "/p", "",
                CanonicalRequest.canonicalHeaders(sub));
        headers.put("x-wop-sign", SignHeader.build("WOP-RSA3072-SHA256", 1800,
                Arrays.asList("x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"),
                Codec.b64UrlEncode(RSA.signature().sign(Codec.utf8(canonical), platformPriv,
                        Codec.utf8("1234567812345678")))));

        assertEquals(VerifyResult.Reason.INVALID_ENCRYPT_HEADER,
                client.verifyResponse(headers, wire, "/p").reason());
    }
}
