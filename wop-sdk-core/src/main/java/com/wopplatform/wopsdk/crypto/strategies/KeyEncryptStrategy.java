package com.wopplatform.wopsdk.crypto.strategies;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * ③ 密钥加密策略（DEK 非对称包装，crypto spec §4.1）。
 */
public interface KeyEncryptStrategy {

    byte[] encrypt(byte[] plainKey, PublicKey publicKey);

    byte[] decrypt(byte[] cipherText, PrivateKey privateKey);

    String algorithmName();
}
