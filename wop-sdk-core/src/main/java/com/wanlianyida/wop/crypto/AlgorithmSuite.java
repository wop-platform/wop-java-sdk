package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.crypto.strategies.Aes256GcmStrategy;
import com.wanlianyida.wop.crypto.strategies.DigestStrategy;
import com.wanlianyida.wop.crypto.strategies.KeyEncryptStrategy;
import com.wanlianyida.wop.crypto.strategies.MessageEncryptStrategy;
import com.wanlianyida.wop.crypto.strategies.RsaOaepKeyEncryptStrategy;
import com.wanlianyida.wop.crypto.strategies.RsaPkcs1SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.Sha256DigestStrategy;
import com.wanlianyida.wop.crypto.strategies.SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2KeyEncryptStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2SignatureStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm3DigestStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm4GcmStrategy;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class AlgorithmSuite {

    private static final Map<String, AlgorithmSuite> REGISTRY = buildRegistry();

    private static final Set<String> KNOWN_KEY_ALGORITHMS =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList("RSA2048", "RSA3072", "RSA4096", "SM2")));
    private static final Set<String> KNOWN_DIGEST_ALGORITHMS =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList("SHA256", "SM3")));

    private static Map<String, AlgorithmSuite> buildRegistry() {
        Map<String, AlgorithmSuite> registry = new LinkedHashMap<>();
        registry.put("WOP-RSA2048-SHA256", new AlgorithmSuite("WOP-RSA2048-SHA256", "RSA", 2048, "SHA256",
                "sha-256", "AES-256-GCM",
                RsaPkcs1SignatureStrategy.INSTANCE, RsaOaepKeyEncryptStrategy.INSTANCE,
                Aes256GcmStrategy.INSTANCE, Sha256DigestStrategy.INSTANCE));
        registry.put("WOP-RSA3072-SHA256", new AlgorithmSuite("WOP-RSA3072-SHA256", "RSA", 3072, "SHA256",
                "sha-256", "AES-256-GCM",
                RsaPkcs1SignatureStrategy.INSTANCE, RsaOaepKeyEncryptStrategy.INSTANCE,
                Aes256GcmStrategy.INSTANCE, Sha256DigestStrategy.INSTANCE));
        registry.put("WOP-RSA4096-SHA256", new AlgorithmSuite("WOP-RSA4096-SHA256", "RSA", 4096, "SHA256",
                "sha-256", "AES-256-GCM",
                RsaPkcs1SignatureStrategy.INSTANCE, RsaOaepKeyEncryptStrategy.INSTANCE,
                Aes256GcmStrategy.INSTANCE, Sha256DigestStrategy.INSTANCE));
        registry.put("WOP-SM2-SM3", new AlgorithmSuite("WOP-SM2-SM3", "SM2", 0, "SM3",
                "sm3", "SM4-GCM",
                Sm2SignatureStrategy.INSTANCE, Sm2KeyEncryptStrategy.INSTANCE,
                Sm4GcmStrategy.INSTANCE, Sm3DigestStrategy.INSTANCE));
        return Collections.unmodifiableMap(registry);
    }

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

    /** 注册表私有构造（唯一装配点，D13）。 */
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

    public static AlgorithmSuite parse(String securityReq) {
        if (securityReq == null || securityReq.trim().isEmpty()) {
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
                            + "'（密钥算法支持 RSA2048/RSA3072/RSA4096/SM2，摘要算法支持 SHA256/SM3）");
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


    public int signatureLength() {
        return "SM2".equals(keyAlgorithm) ? 64 : keyLength / 8;
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

    /** 调试串（含 securityReq）。 */
    @Override
    public String toString() {
        return "AlgorithmSuite[" + securityReq + "]";
    }
}
