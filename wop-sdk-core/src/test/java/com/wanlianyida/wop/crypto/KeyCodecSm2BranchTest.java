package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.strategies.Sm2Support;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KeyCodec/Sm2Support SM2 分支补测（D12）：正面断言密钥实质（未压缩点 X/Y 坐标、
 * d 标量、曲线域），负面断言 message 关键字（"d 标量须在"、"未压缩点"）。
 * 走 KeyCodec 解析路径的用例在方法体内生成随机密钥材料：PIT 以 hotswap 复用同一
 * minion JVM，静态 CACHE 跨 mutant 存活，固定材料首次执行后永久缓存命中、令
 * 解析路径变异体不被执行；每次执行新材料保证始终缓存 miss。
 */
class KeyCodecSm2BranchTest {

    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");
    private static final X9ECParameters X9 = GMNamedCurves.getByName("sm2p256v1");
    private static final BigInteger N = X9.getN();
    private static final BigInteger D0 = new BigInteger(1, Base64.getDecoder()
            .decode(TestVectors.keys("sm2").path("privateDB64").asText()));

    /** d 标量 → 32B 大端无符号（KeyCodec 约定形态）。 */
    private static byte[] scalar32(BigInteger d) {
        byte[] full = d.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(32, full.length);
        System.arraycopy(full, full.length - len, out, 32 - len, len);
        return out;
    }

    /** d 标量 → 04||X||Y 65B 未压缩点（sm2p256v1）。 */
    private static byte[] pointOf(BigInteger d) {
        return X9.getG().multiply(d).normalize().getEncoded(false);
    }

    private static BigInteger xOf(byte[] point) {
        return new BigInteger(1, Arrays.copyOfRange(point, 1, 33));
    }

    private static BigInteger yOf(byte[] point) {
        return new BigInteger(1, Arrays.copyOfRange(point, 33, 65));
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** 方法体内生成随机标量（[1, N-1]）：每次测试执行新材料，保证 KeyCodec CACHE 恒 miss。 */
    private static BigInteger randomScalar() {
        BigInteger d;
        do {
            d = new BigInteger(255, new SecureRandom());
        } while (d.signum() < 1 || d.compareTo(N) >= 0);
        return d;
    }

    @Test
    void rawPointPublicExposesExactCurvePointAndDomain() {
        byte[] point = pointOf(randomScalar());
        ECPublicKey pub = assertInstanceOf(ECPublicKey.class,
                KeyCodec.parsePublicKey(b64(point), SM2));
        // 密钥实质：W 点坐标逐分量等于输入 04||X||Y，曲线域等于 sm2p256v1 阶
        assertEquals(xOf(point), pub.getQ().normalize().getAffineXCoord().toBigInteger());
        assertEquals(yOf(point), pub.getQ().normalize().getAffineYCoord().toBigInteger());
        ECParameterSpec spec = pub.getParameters();
        assertNotNull(spec);
        assertEquals(N, spec.getN());
    }

    @Test
    void rawScalarPrivateExposesExactScalar() {
        BigInteger d = randomScalar();
        PrivateKey priv = KeyCodec.parsePrivateKey(b64(scalar32(d)), SM2);
        assertEquals(d, Sm2TestKeys.dOf(priv));
    }

    @Test
    void spkiAndPkcs8FormsExposeSameMaterial() {
        // SPKI/PKCS8 形态互认：随机标量派生点 → 原始形态解析 → 再以 SPKI/PKCS8 回喂
        BigInteger dPub = randomScalar();
        byte[] point = pointOf(dPub);
        PublicKey raw = KeyCodec.parsePublicKey(b64(point), SM2);
        ECPublicKey spki = assertInstanceOf(ECPublicKey.class,
                KeyCodec.parsePublicKey(b64(raw.getEncoded()), SM2));
        assertEquals(xOf(point), spki.getQ().normalize().getAffineXCoord().toBigInteger());
        assertEquals(yOf(point), spki.getQ().normalize().getAffineYCoord().toBigInteger());
        assertNotNull(spki.getParameters());
        assertEquals(N, spki.getParameters().getN());

        // PKCS#8 形态互认：独立随机标量 → 原始 d 解析 → 再以 PKCS#8 回喂
        BigInteger dPriv = randomScalar();
        PrivateKey rawPriv = KeyCodec.parsePrivateKey(b64(scalar32(dPriv)), SM2);
        PrivateKey pkcs8 = KeyCodec.parsePrivateKey(b64(rawPriv.getEncoded()), SM2);
        assertEquals(dPriv, Sm2TestKeys.dOf(pkcs8));
    }

    @Test
    void scalarZeroRejectedWithDRangeMessage() {
        // 32B 全零 d=0：requireValidD 的 message 是判定信号（包装文案含 "d 标量 Base64"）
        WopError ex = assertThrows(WopError.class,
                () -> KeyCodec.parsePrivateKey(b64(scalar32(BigInteger.ZERO)), SM2));
        assertTrue(ex.getMessage().contains("d 标量须在"));
    }

    @Test
    void scalarAtCurveOrderRejectedWithDRangeMessage() {
        // d == n（越上界）：守卫拒收，message 含 "d 标量须在"
        WopError ex = assertThrows(WopError.class,
                () -> KeyCodec.parsePrivateKey(b64(scalar32(N)), SM2));
        assertTrue(ex.getMessage().contains("d 标量须在"));
    }

    @Test
    void scalarOneAccepted() {
        // d=1 为合法下界标量
        PrivateKey priv = KeyCodec.parsePrivateKey(b64(scalar32(BigInteger.ONE)), SM2);
        assertEquals(BigInteger.ONE, Sm2TestKeys.dOf(priv));
    }

    @Test
    void emptyKeyMaterialRejectedWithEmptyMessage() {
        // requireText 守卫：空材料须以「为空」拒收（剥守卫后走解析失败分支，message 不同）
        WopError pub = assertThrows(WopError.class, () -> KeyCodec.parsePublicKey("  ", SM2));
        assertTrue(pub.getMessage().contains("公钥为空"));
        WopError priv = assertThrows(WopError.class, () -> KeyCodec.parsePrivateKey(null, SM2));
        assertTrue(priv.getMessage().contains("私钥为空"));
    }

    @Test
    void decodePointReturnsExactCoordinates() {
        byte[] point = pointOf(D0.add(BigInteger.valueOf(5)));
        ECPoint decoded = Sm2Support.decodePoint(point);
        assertEquals(xOf(point), decoded.normalize().getAffineXCoord().toBigInteger());
        assertEquals(yOf(point), decoded.normalize().getAffineYCoord().toBigInteger());
    }

    @Test
    void decodePointRejectsNullWrongLengthAndCompressedPrefix() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(null))
                .getMessage().contains("未压缩点"));
        byte[] short64 = new byte[64];
        short64[0] = 0x04;
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(short64))
                .getMessage().contains("未压缩点"));
        byte[] long66 = new byte[66];
        long66[0] = 0x04;
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(long66))
                .getMessage().contains("未压缩点"));
        byte[] compressedPrefix = pointOf(D0.add(BigInteger.valueOf(6)));
        compressedPrefix[0] = 0x03;
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.decodePoint(compressedPrefix))
                .getMessage().contains("未压缩点"));
    }

    @Test
    void requireValidDCoversBoundaryValues() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireValidD(null))
                .getMessage().contains("d 标量"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireValidD(BigInteger.ZERO))
                .getMessage().contains("d 标量"));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Sm2Support.requireValidD(N))
                .getMessage().contains("d 标量"));
        assertDoesNotThrow(() -> Sm2Support.requireValidD(BigInteger.ONE));
        assertDoesNotThrow(() -> Sm2Support.requireValidD(N.subtract(BigInteger.ONE)));
    }

    @Test
    void namedDomainCarriesSm2CurveParameters() {
        ECNamedDomainParameters domain = Sm2Support.namedDomain();
        assertNotNull(domain);
        assertEquals(N, domain.getN());
        assertEquals(X9.getG().normalize().getAffineXCoord().toBigInteger(),
                domain.getG().normalize().getAffineXCoord().toBigInteger());
        assertEquals(X9.getG().normalize().getAffineYCoord().toBigInteger(),
                domain.getG().normalize().getAffineYCoord().toBigInteger());
    }
}
