package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 国际报文加密策略：AES-256-GCM/NoPadding。
 * <p>
 * key 32B / IV 12B（CSPRNG 随机生成，I4：同一对称密钥下 IV 永不复用）/ tag 128bit；
 * 密文 = ciphertext‖tag 尾部拼接（JCA GCM 天然输出形态，F4）。
 */
public final class Aes256GcmStrategy implements MessageEncryptStrategy {

    public static final Aes256GcmStrategy INSTANCE = new Aes256GcmStrategy();

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ALGORITHM = "AES-256-GCM";
    private static final int KEY_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Aes256GcmStrategy() {
    }

    @Override
    public CipherResult encrypt(byte[] plain, byte[] key) {
        return encrypt(plain, key, RANDOM);
    }

    /** IV 取自注入源（确定性钩子；I4 生成点仍在策略内）。 */
    @Override
    public CipherResult encrypt(byte[] plain, byte[] key, SecureRandom random) {
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return encryptForVector(plain, key, iv);
    }

    /** 固定 IV 加密——<b>黄金向量专用</b>（固定 IV 仅为字节级断言，生产违反不变式 I4）。 */
    CipherResult encryptForVector(byte[] plain, byte[] key, byte[] iv) {
        requireKey(key);
        requireIv(iv);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            return new CipherResult(cipher.doFinal(plain), iv);
        } catch (Exception e) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "AES-GCM 加密失败", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipher, byte[] iv, byte[] key) {
        requireKey(key);
        requireIv(iv);
        try {
            Cipher decryptor = Cipher.getInstance(TRANSFORMATION);
            decryptor.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            return decryptor.doFinal(cipher);
        } catch (Exception e) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "AES-GCM 解密失败", e);
        }
    }

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }

    @Override
    public int keyLength() {
        return KEY_LENGTH;
    }

    @Override
    public int ivLength() {
        return IV_LENGTH;
    }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != KEY_LENGTH) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "AES-256 密钥须为 32 字节");
        }
    }

    private static void requireIv(byte[] iv) {
        if (iv == null || iv.length != IV_LENGTH) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "IV 须为 12 字节");
        }
    }
}
