package com.wanlianyida.wop.crypto.strategies;

/**
 * ② 报文加密策略（L2 信封对称加解密，crypto spec §4.1）。
 * 密文与 IV 同生同传（{@link CipherResult}），调用方不可能拿错。
 */
public interface MessageEncryptStrategy {

    CipherResult encrypt(byte[] plain, byte[] key);

    byte[] decrypt(byte[] cipher, byte[] iv, byte[] key);

    String algorithmName();

    int keyLength();

    int ivLength();
}
