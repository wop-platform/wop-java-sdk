package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.BouncyCastleHolder;
import com.wanlianyida.wop.crypto.CryptoException;

import java.security.MessageDigest;
import java.security.Provider;

/**
 * 国密摘要策略：SM3（BC 承接）。
 */
public final class Sm3DigestStrategy implements DigestStrategy {

    public static final Sm3DigestStrategy INSTANCE = new Sm3DigestStrategy();

    private static final String ALGORITHM = "SM3";

    /** 无状态单例，私有构造。 */
    private Sm3DigestStrategy() {
    }

    /** 计算 SM3 摘要（BC 承接）；版本守卫在 try 之外，保证配置错误不被包装为加密失败。 */
    @Override
    public byte[] digest(byte[] data) {
        Provider provider = BouncyCastleHolder.provider();
        try {
            return MessageDigest.getInstance(ALGORITHM, provider).digest(data);
        } catch (Exception e) {
            throw new CryptoException("DIGEST", ALGORITHM, "SM3 摘要失败", e);
        }
    }

    /** 线上算法名 SM3。 */
    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
