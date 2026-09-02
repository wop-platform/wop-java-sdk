package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopSdkException;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 密钥解析（KeyCodec 边缘，D12 分发契约）：字符串入参（PEM 或 Base64 单行）→ JCA Key（缓存解析，D7）。
 * <ul>
 *   <li>RSA：公钥 = X.509 SPKI（PEM 或 Base64）；私钥 = PKCS#8；密钥长度须与套件一致（3072/4096）</li>
 *   <li>SM2：公钥 = 未压缩点 04‖X‖Y 65B（Base64）或 SPKI；私钥 = d 32B 标量（Base64）或 PKCS#8；
 *       曲线守卫 sm2p256v1（I5）</li>
 * </ul>
 * 解析失败抛 {@link WopSdkException}（配置类错误，本地明确——鉴权前可判定，无 oracle 风险）。
 */
public final class KeyCodec {

    private static final ConcurrentHashMap<String, Object> CACHE = new ConcurrentHashMap<>();

    /** 工具类禁实例化。 */
    private KeyCodec() {
    }

    /** 解析公钥（merchant/platform 公钥按套件族路由格式）。 */
    public static PublicKey parsePublicKey(String pemOrBase64, AlgorithmSuite suite) {
        requireText(pemOrBase64, "公钥");
        return (PublicKey) CACHE.computeIfAbsent(cacheKey(suite, "pub", pemOrBase64),
                k -> doParsePublic(stripPem(pemOrBase64), suite));
    }

    /** 解析私钥（签名/解包私钥按套件族路由格式）。 */
    public static PrivateKey parsePrivateKey(String pemOrBase64, AlgorithmSuite suite) {
        requireText(pemOrBase64, "私钥");
        return (PrivateKey) CACHE.computeIfAbsent(cacheKey(suite, "priv", pemOrBase64),
                k -> doParsePrivate(stripPem(pemOrBase64), suite));
    }

    /** 实际解析公钥：RSA=SPKI（含长度校验）；SM2=65B 未压缩点或 SPKI（含曲线守卫）。 */
    private static PublicKey doParsePublic(byte[] der, AlgorithmSuite suite) {
        try {
            if ("RSA".equals(suite.keyAlgorithm())) {
                PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
                requireRsaLength((RSAKey) key, suite);
                return key;
            }
            // SM2：65B 未压缩点（D12）或 SPKI
            if (der.length == 65 && der[0] == 0x04) {
                ECPublicKeyParameters params = new ECPublicKeyParameters(
                        com.wanlianyida.wop.crypto.strategies.Sm2Support.decodePoint(der), sm2Domain());
                byte[] spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params).getEncoded();
                return ecFactory().generatePublic(new X509EncodedKeySpec(spki));
            }
            PublicKey key = ecFactory().generatePublic(new X509EncodedKeySpec(der));
            com.wanlianyida.wop.crypto.strategies.Sm2Support.toPublicParams(key);
            return key;
        } catch (WopSdkException e) {
            throw e;
        } catch (Exception e) {
            throw new WopSdkException("公钥解析失败（" + suite.keyAlgorithm()
                    + "，期望 SPKI 或 SM2 未压缩点 Base64）: " + e.getMessage(), e);
        }
    }

    /** 实际解析私钥：RSA=PKCS#8（含长度校验）；SM2=d 32B 标量或 PKCS#8（含域校验）。 */
    private static PrivateKey doParsePrivate(byte[] der, AlgorithmSuite suite) {
        try {
            if ("RSA".equals(suite.keyAlgorithm())) {
                PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
                requireRsaLength((RSAKey) key, suite);
                return key;
            }
            // SM2：d 32B 标量（D12）或 PKCS#8
            if (der.length == 32) {
                BigInteger d = new BigInteger(1, der);
                com.wanlianyida.wop.crypto.strategies.Sm2Support.requireValidD(d);
                ECPrivateKeyParameters params = new ECPrivateKeyParameters(d, sm2Domain());
                byte[] pkcs8 = PrivateKeyInfoFactory.createPrivateKeyInfo(params).getEncoded();
                return ecFactory().generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            }
            PrivateKey key = ecFactory().generatePrivate(new PKCS8EncodedKeySpec(der));
            com.wanlianyida.wop.crypto.strategies.Sm2Support.toPrivateParams(key);
            return key;
        } catch (WopSdkException e) {
            throw e;
        } catch (Exception e) {
            throw new WopSdkException("私钥解析失败（" + suite.keyAlgorithm()
                    + "，期望 PKCS#8 或 SM2 d 标量 Base64）: " + e.getMessage(), e);
        }
    }

    /** RSA 密钥长度与套件一致（支持类：长度非法）。 */
    private static void requireRsaLength(RSAKey key, AlgorithmSuite suite) {
        int bits = key.getModulus().bitLength();
        if (bits != suite.keyLength()) {
            throw new WopSdkException("RSA 密钥长度 " + bits + " 与套件要求 " + suite.keyLength() + " 不符");
        }
    }

    /** BC Provider 供给的 EC KeyFactory。 */
    private static KeyFactory ecFactory() throws Exception {
        return KeyFactory.getInstance("EC", BouncyCastleHolder.provider());
    }

    /** sm2p256v1 命名曲线域（委托 {@code Sm2Support}）。 */
    private static ECNamedDomainParameters sm2Domain() {
        return com.wanlianyida.wop.crypto.strategies.Sm2Support.namedDomain();
    }

    /** PEM 包装剥离：-----BEGIN/END----- 行去掉，剩余空白全部移除后 base64 解码。 */
    static byte[] stripPem(String pemOrBase64) {
        String text = pemOrBase64.replaceAll("-----BEGIN [A-Z0-9 ]+-----", "")
                .replaceAll("-----END [A-Z0-9 ]+-----", "")
                .replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new WopSdkException("密钥材料非合法 Base64: " + e.getMessage(), e);
        }
    }

    /** 入参非空守卫（空值抛配置类明确异常）。 */
    private static void requireText(String text, String kind) {
        if (text == null || text.trim().isEmpty()) {
            throw new WopSdkException(kind + "为空");
        }
    }

    /** 缓存键（securityReq:kind:hash:长度，避免持有密钥明文串）。 */
    private static String cacheKey(AlgorithmSuite suite, String kind, String key) {
        return suite.securityReq() + ':' + kind + ':' + key.hashCode() + ':' + key.length();
    }
}
