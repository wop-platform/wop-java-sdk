package com.wopplatform.wopsdk.crypto;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * SM2 固定 k 参考签名器（<b>测试专用</b>）：按 GM/T 0009 手写签名数学，
 * 与黄金向量字节级互证；生产路径（BC SM2Signer + CSPRNG k）经 verify 侧钉死。
 */
public final class Sm2FixedKSigner {

    private static final X9ECParameters P = GMNamedCurves.getByName("sm2p256v1");
    private static final byte[] USER_ID = "1234567812345678".getBytes();

    private Sm2FixedKSigner() {
    }

    /** 以显式 k 签名，返回裸 r||s 64B。 */
    public static byte[] sign(byte[] message, PrivateKey privateKey, BigInteger k) {
        BigInteger d = Sm2TestKeys.dOf(privateKey);
        ECPoint q = P.getG().multiply(d).normalize();

        MessageDigest za = sm3();
        za.update(entl(USER_ID));
        za.update(USER_ID);
        za.update(field(P.getCurve().getA()));
        za.update(field(P.getCurve().getB()));
        za.update(field(P.getG().normalize().getAffineXCoord()));
        za.update(field(P.getG().normalize().getAffineYCoord()));
        za.update(field(q.getAffineXCoord()));
        za.update(field(q.getAffineYCoord()));
        byte[] z = za.digest();
        // GM/T 0009 两段式：e = SM3(ZA || M)，ZA 为摘要而非原材料
        MessageDigest emd = sm3();
        emd.update(z);
        emd.update(message);
        BigInteger e = new BigInteger(1, emd.digest());

        ECPoint kG = P.getG().multiply(k).normalize();
        BigInteger n = P.getN();
        BigInteger r = e.add(kG.getAffineXCoord().toBigInteger()).mod(n);
        BigInteger s = d.add(BigInteger.ONE).modInverse(n)
                .multiply(k.subtract(r.multiply(d)).mod(n)).mod(n);
        return concat(fix32(r), fix32(s));
    }

    /** 从公钥取 Q 点（跨实现互证辅助）。 */
    public static byte[] publicPoint(PublicKey publicKey) {
        ECPoint q = com.wopplatform.wopsdk.crypto.strategies.Sm2Support.toPublicParams(publicKey).getQ();
        return q.getEncoded(false);
    }

    static BigInteger kOf(String b64Url) {
        return new BigInteger(1, Codec.b64UrlDecode(b64Url));
    }

    static MessageDigest sm3() {
        try {
            return MessageDigest.getInstance("SM3", BouncyCastleHolder.provider());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] entl(byte[] userId) {
        int bits = userId.length * 8;
        return new byte[]{(byte) (bits >>> 8), (byte) bits};
    }

    private static byte[] field(ECFieldElement element) {
        return element.getEncoded();
    }

    private static byte[] fix32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
