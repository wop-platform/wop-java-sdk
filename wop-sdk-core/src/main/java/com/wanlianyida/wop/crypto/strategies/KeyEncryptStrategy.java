package com.wanlianyida.wop.crypto.strategies;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * ③ 密钥加密策略（DEK 非对称包装，crypto spec §4.1）。
 */
public interface KeyEncryptStrategy {

    byte[] encrypt(byte[] plainKey, PublicKey publicKey);

    /**
     * 指定随机源包装（填充/OAEP seed/k 取自注入源）。
     * <p>确定性钩子（interop 联调合同）：实现未覆写时退回自管 CSPRNG 的 {@link #encrypt(byte[], PublicKey)}。
     */
    default byte[] encrypt(byte[] plainKey, PublicKey publicKey, java.security.SecureRandom random) {
        return encrypt(plainKey, publicKey);
    }

    byte[] decrypt(byte[] cipherText, PrivateKey privateKey);

    String algorithmName();
}
