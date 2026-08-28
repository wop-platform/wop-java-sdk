package com.wopplatform.wopsdk.crypto.strategies;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * SM2 密钥形态守卫与转换（I5 合规边界 + BCEC ↔ BC 轻量参数）。
 * <p>
 * 仅接受 sm2p256v1 推荐曲线域，防非 SM2 EC 密钥静默参与国密运算；
 * 非法输入抛 {@link IllegalArgumentException}，由策略包装为 {@link CryptoException} 或归入模糊失败。
 */
public final class Sm2Support {

    /** SM2 签名/验签默认 userId（与黄金向量一致，协议级常量）。 */
    public static final byte[] DEFAULT_USER_ID = "1234567812345678".getBytes();

    private Sm2Support() {
    }


    /** sm2p256v1 命名曲线域（含 OID，供 SPKI/PKCS#8 构造）。 */
    public static org.bouncycastle.crypto.params.ECNamedDomainParameters namedDomain() {
        return Sm2DomainHolder.NAMED;
    }
    /** JCA BCEC 公钥 → BC 轻量参数（曲线守卫）。 */
    public static ECPublicKeyParameters toPublicParams(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey ec) || ec.getParameters() == null) {
            throw new IllegalArgumentException("公钥非 SM2 椭圆曲线密钥（缺少命名曲线参数）");
        }
        ECDomainParameters domain = domainOf(ec.getParameters());
        return new ECPublicKeyParameters(ec.getQ(), domain);
    }

    /** JCA BCEC 私钥 → BC 轻量参数（曲线守卫）。 */
    public static ECPrivateKeyParameters toPrivateParams(PrivateKey privateKey) {
        if (!(privateKey instanceof ECPrivateKey ec) || ec.getParameters() == null) {
            throw new IllegalArgumentException("私钥非 SM2 椭圆曲线密钥（缺少命名曲线参数）");
        }
        ECDomainParameters domain = domainOf(ec.getParameters());
        return new ECPrivateKeyParameters(ec.getD(), domain);
    }

    /** 曲线守卫：密钥自带域须与 SM2 推荐曲线 sm2p256v1 一致。 */
    public static void requireSm2Domain(ECDomainParameters domain) {
        ECDomainParameters sm2 = Sm2DomainHolder.SM2;
        if (domain == null
                || !domain.getN().equals(sm2.getN())
                || !domain.getG().normalize().equals(sm2.getG().normalize())
                || !domain.getCurve().getA().toBigInteger().equals(sm2.getCurve().getA().toBigInteger())
                || !domain.getCurve().getB().toBigInteger().equals(sm2.getCurve().getB().toBigInteger())) {
            throw new IllegalArgumentException("密钥曲线非 SM2 推荐曲线 sm2p256v1");
        }
    }

    /** 未压缩点 04||X||Y（65B）→ 曲线点（decodePoint 自带曲线合法性校验）。 */
    public static ECPoint decodePoint(byte[] point65) {
        if (point65 == null || point65.length != 65 || point65[0] != 0x04) {
            throw new IllegalArgumentException("SM2 公钥须为未压缩点 04||X||Y（65 字节，D12）");
        }
        return Sm2DomainHolder.CURVE.decodePoint(point65);
    }

    /** d 标量范围校验：1 <= d <= n-1。 */
    public static void requireValidD(BigInteger d) {
        if (d == null || d.signum() < 1 || d.compareTo(Sm2DomainHolder.N) >= 0) {
            throw new IllegalArgumentException("SM2 私钥 d 标量须在 [1, n-1]");
        }
    }

    private static ECDomainParameters domainOf(org.bouncycastle.jce.spec.ECParameterSpec spec) {
        ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        requireSm2Domain(domain);
        return domain;
    }
}
