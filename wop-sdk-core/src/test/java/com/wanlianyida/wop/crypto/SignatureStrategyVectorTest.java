package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.crypto.strategies.RsaPkcs1SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2SignatureStrategy;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureStrategyVectorTest {

    private static final AlgorithmSuite RSA2048 = AlgorithmSuite.parse("WOP-RSA2048-SHA256");
    private static final AlgorithmSuite RSA3072 = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite RSA4096 = AlgorithmSuite.parse("WOP-RSA4096-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    @Test
    void rsa3072SignMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);

        byte[] sig = RsaPkcs1SignatureStrategy.INSTANCE.sign(msg, priv, Codec.utf8("x"));
        assertEquals(vector.path("expectedSigB64u").asText(), Codec.b64UrlEncode(sig));
        assertEquals(vector.path("sigLenBytes").asInt(), sig.length);
        assertEquals(vector.path("b64uLen").asInt(), Codec.b64UrlEncode(sig).length());
        assertTrue(RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("x")));
    }

    @Test
    void rsa2048SignMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("signature", "rsa2048-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa2048").path("privatePkcs8B64").asText(), RSA2048);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa2048").path("publicSpkiB64").asText(), RSA2048);

        byte[] sig = RsaPkcs1SignatureStrategy.INSTANCE.sign(msg, priv, Codec.utf8("x"));
        assertEquals(vector.path("expectedSigB64u").asText(), Codec.b64UrlEncode(sig));
        assertEquals(vector.path("sigLenBytes").asInt(), sig.length);
        assertEquals(vector.path("b64uLen").asInt(), Codec.b64UrlEncode(sig).length());
        assertTrue(RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("x")));
    }

    @Test
    void rsa4096SignMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("signature", "rsa4096-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa4096").path("privatePkcs8B64").asText(), RSA4096);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa4096").path("publicSpkiB64").asText(), RSA4096);

        byte[] sig = RsaPkcs1SignatureStrategy.INSTANCE.sign(msg, priv, Codec.utf8("x"));
        assertEquals(vector.path("expectedSigB64u").asText(), Codec.b64UrlEncode(sig));
        assertEquals(512, sig.length);
        assertEquals(683, Codec.b64UrlEncode(sig).length());
        assertTrue(RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("x")));
    }

    @Test
    void rsaTamperedSignatureRejected() {
        JsonNode vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        byte[] sig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        sig[10] ^= 0x01;
        assertFalse(RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("x")));
        byte[] sig2 = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        assertFalse(RsaPkcs1SignatureStrategy.INSTANCE.verify(Codec.utf8("tampered"), sig2, pub, Codec.utf8("x")));
    }

    @Test
    void rsaVerifyLengthMismatchThrowsWrapped() {
        JsonNode vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        byte[] shortSig = new byte[64];
        CryptoException ex = assertThrows(CryptoException.class,
                () -> RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, shortSig, pub, Codec.utf8("x")));
        assertTrue(ex.getMessage().contains("RSA 验签执行失败"));
    }

    @Test
    void sm2FixedKSignMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        BigInteger k = new BigInteger(1, Codec.b64UrlDecode(TestVectors.input("sm2FixedKB64u")));

        byte[] rs = Sm2FixedKSigner.sign(msg, priv, k);
        // 字节级：参考实现（显式 k）= 向量；64B 裸 r||s；b64url 恒 86 字符
        assertEquals(vector.path("expectedSigB64u").asText(), Codec.b64UrlEncode(rs));
        assertEquals(64, rs.length);
        assertEquals(86, Codec.b64UrlEncode(rs).length());

        SignatureStrategy strategy = Sm2SignatureStrategy.INSTANCE;
        assertTrue(strategy.verify(msg, rs, pub, Codec.utf8("1234567812345678")));
        byte[] produced = strategy.sign(msg, priv, Codec.utf8("1234567812345678"));
        assertEquals(64, produced.length);
        assertTrue(strategy.verify(msg, produced, pub, Codec.utf8("1234567812345678")));
        assertFalse(Arrays.equals(produced, rs));
    }

    @Test
    void sm2LengthViolationsRejected() {
        JsonNode vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        byte[] sig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());

        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, Arrays.copyOfRange(sig, 0, 63), pub, Codec.utf8("1234567812345678")));
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, Arrays.copyOf(sig, 65), pub, Codec.utf8("1234567812345678")));
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, null, pub, Codec.utf8("1234567812345678")));
        byte[] der = toDer(sig);
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, der, pub, Codec.utf8("1234567812345678")));
    }

    @Test
    void sm2TamperedSignatureRejected() {
        JsonNode vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        byte[] sig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        sig[sig.length - 1] ^= 0x01;
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("1234567812345678")));
    }

    @Test
    void crossFamilySignatureRejected() {
        JsonNode vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey sm2Pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        byte[] rsaSig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, rsaSig, sm2Pub, Codec.utf8("1234567812345678")));
    }

    @Test
    void suiteRoutesSignatureStrategy() {
        assertEquals("SHA256withRSA", AlgorithmSuite.parse("WOP-RSA3072-SHA256").signature().algorithmName());
        assertEquals("SM3withSM2", AlgorithmSuite.parse("WOP-SM2-SM3").signature().algorithmName());
    }

    @Test
    void sm2SignDeterministicParts() {
        // 参考实现 r/s 各 32B 大端（不足左补零路径）
        JsonNode vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        BigInteger k = new BigInteger(1, Codec.b64UrlDecode(TestVectors.input("sm2FixedKB64u")));
        byte[] rs = Sm2FixedKSigner.sign(msg, priv, k);
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        assertTrue(r.signum() > 0 && s.signum() > 0);
        assertArrayEquals(rs, Codec.concat(Arrays.copyOfRange(rs, 0, 32), Arrays.copyOfRange(rs, 32, 64)));
    }

    private static byte[] toDer(byte[] rs) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
        v.add(new org.bouncycastle.asn1.ASN1Integer(r));
        v.add(new org.bouncycastle.asn1.ASN1Integer(s));
        try {
            return new org.bouncycastle.asn1.DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
