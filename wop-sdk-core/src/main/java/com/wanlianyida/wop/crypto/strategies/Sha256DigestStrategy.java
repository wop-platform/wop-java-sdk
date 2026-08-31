package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;

import java.security.MessageDigest;

/**
 * 国际摘要策略：SHA-256。
 */
public final class Sha256DigestStrategy implements DigestStrategy {

    public static final Sha256DigestStrategy INSTANCE = new Sha256DigestStrategy();

    private static final String ALGORITHM = "SHA-256";

    /** 无状态单例，私有构造。 */
    private Sha256DigestStrategy() {
    }

    /** 计算 SHA-256 摘要。 */
    @Override
    public byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(data);
        } catch (Exception e) {
            throw new CryptoException("DIGEST", ALGORITHM, "SHA-256 摘要失败", e);
        }
    }

    /** 线上算法名 SHA-256。 */
    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
