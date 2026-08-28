package com.wopplatform.wopsdk.crypto.strategies;

import com.wopplatform.wopsdk.crypto.BouncyCastleHolder;
import com.wopplatform.wopsdk.crypto.CryptoException;

import java.security.MessageDigest;

/**
 * 国密摘要策略：SM3（BC 承接）。
 */
public final class Sm3DigestStrategy implements DigestStrategy {

    public static final Sm3DigestStrategy INSTANCE = new Sm3DigestStrategy();

    private static final String ALGORITHM = "SM3";

    private Sm3DigestStrategy() {
    }

    @Override
    public byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance(ALGORITHM, BouncyCastleHolder.provider()).digest(data);
        } catch (Exception e) {
            throw new CryptoException("DIGEST", ALGORITHM, "SM3 摘要失败", e);
        }
    }

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
