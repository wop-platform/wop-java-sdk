package com.wopplatform.wopsdk.crypto.strategies;

import com.wopplatform.wopsdk.crypto.CryptoException;

import java.security.MessageDigest;

/**
 * 国际摘要策略：SHA-256。
 */
public final class Sha256DigestStrategy implements DigestStrategy {

    public static final Sha256DigestStrategy INSTANCE = new Sha256DigestStrategy();

    private static final String ALGORITHM = "SHA-256";

    private Sha256DigestStrategy() {
    }

    @Override
    public byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(data);
        } catch (Exception e) {
            throw new CryptoException("DIGEST", ALGORITHM, "SHA-256 摘要失败", e);
        }
    }

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
