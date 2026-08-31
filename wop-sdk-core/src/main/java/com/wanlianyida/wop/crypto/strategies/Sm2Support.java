package com.wanlianyida.wop.crypto.strategies;

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
 * 仅接受 sm2p256v1 推荐曲线域（指纹整体比较，防非 SM2 EC 密钥静默参与国密运算）；
 * 非法输入抛 {@link IllegalArgumentException}，由策略包装为 {@link com.wanlianyida.wop.crypto.CryptoException} 或归入模糊失败。
 * <p>
 * SM2 签名 userId（D14）无默认值：出向 = x-wop-appkey、入向 = 平台协议固定值
 * {@code "1234567812345678"}（见 WopClient.PLATFORM_SIGN_USER_ID），由调用方显式传入。
 */
public final class Sm2Support {

    /** 工具类禁实例化。 */
    private Sm2Support() {
    }

    /** JCA BCEC 公钥 → BC 轻量参数（曲线守卫）。 */
    public static ECPublicKeyParameters toPublicParams(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey ec)) {
            throw new IllegalArgumentException("公钥非 SM2 椭圆曲线密钥");
        }
        return new ECPublicKeyParameters(ec.getQ(), domainOf(ec.getParameters()));
    }

    /** sm2p256v1 命名曲线域（含 OID，供 SPKI/PKCS#8 构造）。 */
    public static org.bouncycastle.crypto.params.ECNamedDomainParameters namedDomain() {
        return Sm2DomainHolder.NAMED;
    }

    /** JCA BCEC 私钥 → BC 轻量参数（曲线守卫）。 */
    public static ECPrivateKeyParameters toPrivateParams(PrivateKey privateKey) {
        if (!(privateKey instanceof ECPrivateKey ec)) {
            throw new IllegalArgumentException("私钥非 SM2 椭圆曲线密钥");
        }
        return new ECPrivateKeyParameters(ec.getD(), domainOf(ec.getParameters()));
    }

    /** 曲线守卫：密钥自带域指纹须与 SM2 推荐曲线 sm2p256v1 完全一致。 */
    public static void requireSm2Domain(ECDomainParameters domain) {
        if (domain == null || !fingerprint(domain).equals(Sm2DomainHolder.FINGERPRINT)) {
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

    /** d 标量范围校验：{@code 1 <= d <= n-1}。 */
    public static void requireValidD(BigInteger d) {
        if (d == null || d.signum() < 1 || d.compareTo(Sm2DomainHolder.N) >= 0) {
            throw new IllegalArgumentException("SM2 私钥 d 标量须在 [1, n-1]");
        }
    }

    /** BCEC 参数 → BC 轻量域参数（含 sm2p256v1 曲线守卫，I5）。 */
    private static ECDomainParameters domainOf(org.bouncycastle.jce.spec.ECParameterSpec spec) {
        ECDomainParameters domain = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        requireSm2Domain(domain);
        return domain;
    }

    /** 域指纹：n|a|b|Gx|Gy 十六进制拼接（无短路分支）。 */
    private static String fingerprint(ECDomainParameters domain) {
        ECPoint g = domain.getG().normalize();
        return domain.getN().toString(16) + '|'
                + domain.getCurve().getA().toBigInteger().toString(16) + '|'
                + domain.getCurve().getB().toBigInteger().toString(16) + '|'
                + g.getAffineXCoord().toBigInteger().toString(16) + '|'
                + g.getAffineYCoord().toBigInteger().toString(16);
    }
}
