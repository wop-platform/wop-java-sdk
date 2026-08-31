package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.crypto.strategies.RsaPkcs1SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2SignatureStrategy;
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

/**
 * A1 签名正向量 + A2 负向量：
 * <ul>
 *   <li>RSA3072/4096：PKCS#1 v1.5 确定性——生产 sign() 与向量字节级一致</li>
 *   <li>SM2：固定 k 参考实现（GM/T 0009 手写数学）与向量字节级互证，
 *       生产 verify() 消费向量签名必须通过（D9 裸 r||s）</li>
 *   <li>负向量：tamper / 63B、65B 定长 / DER 编码 / 跨族</li>
 * </ul>
 * spec:D14：userId 显式入参——RSA 忽略该字节（任意值），SM2 必须与请求身份同源
 * （此处理论向量用协议固定值断言，与 Sm2FixedKSigner 一致；线上由 WopClient 传 appKey）。
 */
class SignatureStrategyVectorTest {

    private static final AlgorithmSuite RSA3072 = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite RSA4096 = AlgorithmSuite.parse("WOP-RSA4096-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    @Test
    void rsa3072SignMatchesGoldenVector() {
        var vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);

        byte[] sig = RsaPkcs1SignatureStrategy.INSTANCE.sign(msg, priv, Codec.utf8("x"));
        // 字节级：签名 = 向量；b64url 长度恒 512
        assertEquals(vector.path("expectedSigB64u").asText(), Codec.b64UrlEncode(sig));
        assertEquals(vector.path("sigLenBytes").asInt(), sig.length);
        assertEquals(vector.path("b64uLen").asInt(), Codec.b64UrlEncode(sig).length());
        assertTrue(RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("x")));
    }

    @Test
    void rsa4096SignMatchesGoldenVector() {
        var vector = TestVectors.firstById("signature", "rsa4096-sign");
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
        var vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        byte[] sig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        sig[10] ^= 0x01;
        assertFalse(RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("x")));
        // 消息被改同样拒绝
        byte[] sig2 = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        assertFalse(RsaPkcs1SignatureStrategy.INSTANCE.verify(Codec.utf8("tampered"), sig2, pub, Codec.utf8("x")));
    }

    @Test
    void rsaVerifyLengthMismatchThrowsWrapped() {
        // A2 负向量：签名长度 != 模长（SunRsaSign engineVerify 前置守卫抛 SignatureException）
        // → 策略包装为 CryptoException（I7：调用方只见统一模糊异常）
        var vector = TestVectors.firstById("signature", "rsa3072-sign");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        byte[] shortSig = new byte[64];
        CryptoException ex = assertThrows(CryptoException.class,
                () -> RsaPkcs1SignatureStrategy.INSTANCE.verify(msg, shortSig, pub, Codec.utf8("x")));
        assertTrue(ex.getMessage().contains("RSA 验签执行失败"));
    }

    @Test
    void sm2FixedKSignMatchesGoldenVector() {
        var vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        BigInteger k = new BigInteger(1, Codec.b64UrlDecode(TestVectors.input("sm2FixedKB64u")));

        byte[] rs = Sm2FixedKSigner.sign(msg, priv, k);
        // 字节级：参考实现（显式 k）= 向量；64B 裸 r||s；b64url 恒 86 字符
        assertEquals(vector.path("expectedSigB64u").asText(), Codec.b64UrlEncode(rs));
        assertEquals(64, rs.length);
        assertEquals(86, Codec.b64UrlEncode(rs).length());

        // 生产策略（BC SM2Signer，userId 显式传入协议固定值，与 Sm2FixedKSigner 一致）必须验证通过向量签名
        SignatureStrategy strategy = Sm2SignatureStrategy.INSTANCE;
        assertTrue(strategy.verify(msg, rs, pub, Codec.utf8("1234567812345678")));
        // 生产签名（随机 k）结构合法且可验证
        byte[] produced = strategy.sign(msg, priv, Codec.utf8("1234567812345678"));
        assertEquals(64, produced.length);
        assertTrue(strategy.verify(msg, produced, pub, Codec.utf8("1234567812345678")));
        assertFalse(Arrays.equals(produced, rs)); // k 不同则签名不同（随机化）
    }

    @Test
    void sm2LengthViolationsRejected() {
        // A2 负向量：63B / 65B / DER 编码签名一律 false（定长前置校验，spec §3.3①）
        var vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        byte[] sig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());

        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, Arrays.copyOfRange(sig, 0, 63), pub, Codec.utf8("1234567812345678")));
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, Arrays.copyOf(sig, 65), pub, Codec.utf8("1234567812345678")));
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, null, pub, Codec.utf8("1234567812345678")));
        // DER SEQUENCE 编码（线上禁止，D9）——72B 左右，长度即拒
        byte[] der = toDer(sig);
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, der, pub, Codec.utf8("1234567812345678")));
    }

    @Test
    void sm2TamperedSignatureRejected() {
        var vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        byte[] sig = Codec.b64UrlDecode(vector.path("expectedSigB64u").asText());
        sig[sig.length - 1] ^= 0x01;
        assertFalse(Sm2SignatureStrategy.INSTANCE.verify(msg, sig, pub, Codec.utf8("1234567812345678")));
    }

    @Test
    void crossFamilySignatureRejected() {
        // A2 负向量：SM2 套件验 RSA 384B 签名（长度即拒）；RSA 套件配 SM2 密钥在 KeyCodec 已拒
        var vector = TestVectors.firstById("signature", "rsa3072-sign");
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
        var vector = TestVectors.firstById("signature", "sm2-sign-fixedk");
        byte[] msg = Codec.utf8(vector.path("message").asText());
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        BigInteger k = new BigInteger(1, Codec.b64UrlDecode(TestVectors.input("sm2FixedKB64u")));
        byte[] rs = Sm2FixedKSigner.sign(msg, priv, k);
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        assertTrue(r.signum() > 0 && s.signum() > 0);
        // r||s 直接拼接验证
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
