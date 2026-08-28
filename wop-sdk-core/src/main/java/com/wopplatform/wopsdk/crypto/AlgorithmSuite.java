package com.wopplatform.wopsdk.crypto;

import com.wopplatform.wopsdk.crypto.strategies.Aes256GcmStrategy;
import com.wopplatform.wopsdk.crypto.strategies.DigestStrategy;
import com.wopplatform.wopsdk.crypto.strategies.KeyEncryptStrategy;
import com.wopplatform.wopsdk.crypto.strategies.MessageEncryptStrategy;
import com.wopplatform.wopsdk.crypto.strategies.RsaOaepKeyEncryptStrategy;
import com.wopplatform.wopsdk.crypto.strategies.RsaPkcs1SignatureStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sha256DigestStrategy;
import com.wopplatform.wopsdk.crypto.strategies.SignatureStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm2KeyEncryptStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm2SignatureStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm3DigestStrategy;
import com.wopplatform.wopsdk.crypto.strategies.Sm4GcmStrategy;

import java.util.Map;
import java.util.Set;

/**
 * 算法套件（F1，crypto spec §3/§4.4）：securityReq 原子解析 → 四维策略 + 协议标签。
 * <p>
 * 不可变；策略为无状态进程级单例（D7）；映射集中注册、无运行时配置入口（D13/R5）。
 * 解析规则（spec §2）：
 * <ul>
 *   <li>空值/空白、非三段式、前缀非 WOP → {@link WopSuiteException.Kind#PARSE}（明确）</li>
 *   <li>密钥/摘要算法不在支持列表、跨族组合 → {@link WopSuiteException.Kind#UNSUPPORTED}（明确）</li>
 * </ul>
 */
public final class AlgorithmSuite {

    /** 唯一注册表：合法 securityReq → 套件（D13）。 */
    private static final Map<String, AlgorithmSuite> REGISTRY = Map.of(
            "WOP-RSA3072-SHA256", new AlgorithmSuite("WOP-RSA3072-SHA256", "RSA", 3072, "SHA256",
                    "sha-256", "AES-256-GCM",
                    RsaPkcs1SignatureStrategy.INSTANCE, RsaOaepKeyEncryptStrategy.INSTANCE,
                    Aes256GcmStrategy.INSTANCE, Sha256DigestStrategy.INSTANCE),
            "WOP-RSA4096-SHA256", new AlgorithmSuite("WOP-RSA4096-SHA256", "RSA", 4096, "SHA256",
                    "sha-256", "AES-256-GCM",
                    RsaPkcs1SignatureStrategy.INSTANCE, RsaOaepKeyEncryptStrategy.INSTANCE,
                    Aes256GcmStrategy.INSTANCE, Sha256DigestStrategy.INSTANCE),
            "WOP-SM2-SM3", new AlgorithmSuite("WOP-SM2-SM3", "SM2", 0, "SM3",
                    "sm3", "SM4-GCM",
                    Sm2SignatureStrategy.INSTANCE, Sm2KeyEncryptStrategy.INSTANCE,
                    Sm4GcmStrategy.INSTANCE, Sm3DigestStrategy.INSTANCE));

    private static final Set<String> KNOWN_KEY_ALGORITHMS = Set.of("RSA3072", "RSA4096", "SM2");
    private static final Set<String> KNOWN_DIGEST_ALGORITHMS = Set.of("SHA256", "SM3");

    private final String securityReq;
    private final String keyAlgorithm;
    private final int keyLength;
    private final String digestAlgorithm;
    private final String digestLabel;
    private final String expectedDekAlg;
    private final SignatureStrategy signature;
    private final KeyEncryptStrategy keyEncrypt;
    private final MessageEncryptStrategy messageEncrypt;
    private final DigestStrategy digest;

    private AlgorithmSuite(String securityReq, String keyAlgorithm, int keyLength, String digestAlgorithm,
                           String digestLabel, String expectedDekAlg,
                           SignatureStrategy signature, KeyEncryptStrategy keyEncrypt,
                           MessageEncryptStrategy messageEncrypt, DigestStrategy digest) {
        this.securityReq = securityReq;
        this.keyAlgorithm = keyAlgorithm;
        this.keyLength = keyLength;
        this.digestAlgorithm = digestAlgorithm;
        this.digestLabel = digestLabel;
        this.expectedDekAlg = expectedDekAlg;
        this.signature = signature;
        this.keyEncrypt = keyEncrypt;
        this.messageEncrypt = messageEncrypt;
        this.digest = digest;
    }

    /** 解析 securityReq：先纯格式校验，再查注册表（合法组合的原子装配）。 */
    public static AlgorithmSuite parse(String securityReq) {
        if (securityReq == null || securityReq.isBlank()) {
            throw new WopSuiteException(WopSuiteException.Kind.PARSE, "securityReq 为空（期望 WOP-<密钥算法>-<摘要算法>）");
        }
        String[] segments = securityReq.trim().split("-");
        if (segments.length != 3 || !"WOP".equals(segments[0])) {
            throw new WopSuiteException(WopSuiteException.Kind.PARSE,
                    "securityReq 格式错误: '" + securityReq + "'（期望三段式 WOP-<密钥算法>-<摘要算法>）");
        }
        AlgorithmSuite suite = REGISTRY.get(securityReq.trim());
        if (suite != null) {
            return suite;
        }
        // 组合非法：区分"算法不在列表"与"跨族"，均属支持类
        boolean knownKey = KNOWN_KEY_ALGORITHMS.contains(segments[1]);
        boolean knownDigest = KNOWN_DIGEST_ALGORITHMS.contains(segments[2]);
        if (!knownKey || !knownDigest) {
            throw new WopSuiteException(WopSuiteException.Kind.UNSUPPORTED,
                    "不支持的算法: '" + (knownKey ? segments[2] : segments[1])
                            + "'（密钥算法支持 RSA3072/RSA4096/SM2，摘要算法支持 SHA256/SM3）");
        }
        throw new WopSuiteException(WopSuiteException.Kind.UNSUPPORTED,
                "不支持的算法组合: '" + securityReq + "'（国际密钥配国际摘要、国密密钥配国密摘要，跨族禁止）");
    }

    public String securityReq() {
        return securityReq;
    }

    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    /** RSA 3072/4096；SM2 为 0（曲线固定 sm2p256v1）。 */
    public int keyLength() {
        return keyLength;
    }

    public String digestAlgorithm() {
        return digestAlgorithm;
    }

    /** x-wop-content-digest 算法标签（D2）：sha-256 仅 RSA 族、sm3 仅 SM2 族。 */
    public String digestLabel() {
        return digestLabel;
    }

    /** DEK 载荷期望 alg（6.2）：RSA 族 AES-256-GCM、SM2 族 SM4-GCM。 */
    public String expectedDekAlg() {
        return expectedDekAlg;
    }

    public SignatureStrategy signature() {
        return signature;
    }

    public KeyEncryptStrategy keyEncrypt() {
        return keyEncrypt;
    }

    public MessageEncryptStrategy messageEncrypt() {
        return messageEncrypt;
    }

    public DigestStrategy digest() {
        return digest;
    }

    @Override
    public String toString() {
        return "AlgorithmSuite[" + securityReq + "]";
    }
}
