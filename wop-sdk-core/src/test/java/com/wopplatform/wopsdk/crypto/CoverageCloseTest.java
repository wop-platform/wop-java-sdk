package com.wopplatform.wopsdk.crypto;

import com.wopplatform.wopsdk.WopSdkException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import com.wopplatform.wopsdk.crypto.strategies.Aes256GcmStrategy;
import com.wopplatform.wopsdk.crypto.strategies.RsaOaepKeyEncryptStrategy;
import com.wopplatform.wopsdk.crypto.strategies.RsaPkcs1SignatureStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sha256DigestStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm2KeyEncryptStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm2SignatureStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm2Support;
import com.wopplatform.wopsdk.crypto.strategies.Sm3DigestStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm4GcmStrategy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 覆盖闭合：错误分支（catch/守卫）、边界输入与辅助方法。
 */
class CoverageCloseTest {

    private static final AlgorithmSuite RSA = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    // ==================== 策略错误分支 ====================

    @Test
    void digestStrategiesRejectNull() {
        assertThrows(CryptoException.class, () -> Sha256DigestStrategy.INSTANCE.digest(null));
        assertThrows(CryptoException.class, () -> Sm3DigestStrategy.INSTANCE.digest(null));
    }

    @Test
    void aesGcmNullArgumentsHitCatch() {
        byte[] key = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.encrypt(null, key));
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.decrypt(null, new byte[12], key));
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.encrypt(Codec.utf8("x"), new byte[15]));
    }

    @Test
    void sm4GcmNullArgumentsHitCatch() {
        byte[] key = Codec.b64UrlDecode(TestVectors.input("sm4KeyB64u"));
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.encrypt(null, key));
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.decrypt(null, new byte[12], key));
    }

    @Test
    void rsaOaepRejectsNullAndOversized() {
        java.security.PublicKey pub = KeyCodec.parsePublicKey(
                TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA);
        assertThrows(CryptoException.class,
                () -> RsaOaepKeyEncryptStrategy.INSTANCE.encrypt(null, pub));
        // 400B 超 OAEP 容量（3072bit - 2*256bit - 16 = 336B）
        assertThrows(CryptoException.class,
                () -> RsaOaepKeyEncryptStrategy.INSTANCE.encrypt(new byte[400], pub));
        assertThrows(CryptoException.class,
                () -> RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(null,
                        KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA)));
    }

    @Test
    void rsaSignatureRejectsNullData() {
        java.security.PrivateKey priv = KeyCodec.parsePrivateKey(
                TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA);
        assertThrows(CryptoException.class, () -> RsaPkcs1SignatureStrategy.INSTANCE.sign(null, priv));
    }

    @Test
    void sm2StrategiesWrapFailures() {
        java.security.PublicKey pub = KeyCodec.parsePublicKey(
                TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        java.security.PrivateKey priv = KeyCodec.parsePrivateKey(
                TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        assertThrows(CryptoException.class, () -> Sm2KeyEncryptStrategy.INSTANCE.encrypt(null, pub));
        assertThrows(CryptoException.class, () -> Sm2KeyEncryptStrategy.INSTANCE.decrypt(null, priv));
        assertThrows(CryptoException.class, () -> Sm2SignatureStrategy.INSTANCE.sign(null, priv));
    }

    @Test
    void nonSm2CurveKeyRejected() throws Exception {
        // secp256r1 密钥喂 SM2 策略：曲线守卫逐项拒绝（I5）
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        assertThrows(CryptoException.class,
                () -> Sm2SignatureStrategy.INSTANCE.verify(Codec.utf8("m"), new byte[64], pair.getPublic()));
        assertThrows(CryptoException.class,
                () -> Sm2SignatureStrategy.INSTANCE.sign(Codec.utf8("m"), pair.getPrivate()));
        assertThrows(CryptoException.class,
                () -> Sm2KeyEncryptStrategy.INSTANCE.encrypt(Codec.utf8("m"), pair.getPublic()));
        assertThrows(CryptoException.class,
                () -> Sm2KeyEncryptStrategy.INSTANCE.decrypt(new byte[100], pair.getPrivate()));
        // 非 EC 密钥（null 之外的形态非法）——null 直接拒绝
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.toPublicParams(null));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.toPrivateParams(null));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(null));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(new byte[64]));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireValidD(null));
        assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireSm2Domain(null));
    }

    // ==================== Codec / 载荷边界 ====================

    @Test
    void codecEdgeCases() {
        assertEquals("", Codec.hexLower(null));
        assertArrayEquals(new byte[0], Codec.utf8(null));
        assertArrayEquals(new byte[0], Codec.concat());
        assertFalse(Codec.isLowerHex64("g".repeat(64)));
        assertFalse(Codec.isLowerHex64("0".repeat(32)));
    }

    @Test
    void dekPayloadEncodeRejectsIncompleteFields() {
        assertThrows(WopSdkException.class, () -> DekPayload.encode(null));
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("", new byte[16], new byte[12])));
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("AES-256-GCM", new byte[0], new byte[12])));
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("AES-256-GCM", new byte[16], null)));
        // toString 不泄密钥
        assertFalse(DekPayload.decode(TestVectors.firstById("dekPayload", "dek-rsa")
                .path("expected").asText()).toString().contains("AAEC"));
    }

    @Test
    void encryptedEnvelopeRejectsMalformed() {
        assertThrows(WopSdkException.class, () -> EncryptedEnvelope.cipherOf(null));
        assertThrows(WopSdkException.class, () -> EncryptedEnvelope.cipherOf(new byte[0]));
        assertThrows(WopSdkException.class, () -> EncryptedEnvelope.cipherOf(Codec.utf8("not-json")));
        assertThrows(WopSdkException.class, () -> EncryptedEnvelope.cipherOf(Codec.utf8("{\"encrypted\":\"ab+c\"}")));
        assertThrows(WopSdkException.class, () -> EncryptedEnvelope.cipherOf(Codec.utf8("{\"encrypted\":\"\"}")));
        assertThrows(WopSdkException.class, () -> EncryptedEnvelope.cipherOf(Codec.utf8("{\"encrypted\":\"AAA\"}x")));
        // 合法带空白包裹
        assertTrue(EncryptedEnvelope.cipherOf(Codec.utf8("  {\"encrypted\":\"AAEC\"}  ")).length == 3);
        // roundtrip
        byte[] wrapped = EncryptedEnvelope.wrap("AAEC");
        assertArrayEquals(new byte[]{0, 1, 2}, EncryptedEnvelope.cipherOf(wrapped));
    }

    @Test
    void canonicalRequestSingleHeaderAndEdges() {
        assertEquals("a:1", CanonicalRequest.canonicalHeaders(java.util.Map.of("a", "1")));
        assertEquals("", CanonicalRequest.canonicalHeaders(java.util.Map.of()));
        assertEquals("", CanonicalRequest.urlencode(""));
        assertEquals("", CanonicalRequest.trimall(" "));
    }

    @Test
    void signHeaderToleratesSurroundingWhitespace() {
        SignHeader.Parsed parsed = SignHeader.parse("  WOP-RSA3072-SHA256 v1/60/a/b  ");
        assertEquals("WOP-RSA3072-SHA256", parsed.securityReq());
        assertEquals("b", parsed.signature());
    }

    @Test
    void keyCodecEdgeBranches() {
        // 65B 但首字节非 04 → 走 SPKI 解析失败
        byte[] notPoint = new byte[65];
        notPoint[0] = 0x02;
        assertThrows(WopSdkException.class, () -> KeyCodec.parsePublicKey(
                java.util.Base64.getEncoder().encodeToString(notPoint), SM2));
        // PEM 无 body
        assertThrows(WopSdkException.class, () -> KeyCodec.stripPem("-----BEGIN PUBLIC KEY-----x-----END PUBLIC KEY-----"));
    }

    @Test
    void suiteToString() {
        assertEquals("AlgorithmSuite[WOP-SM2-SM3]", AlgorithmSuite.parse("WOP-SM2-SM3").toString());
    }
}
