package com.wopplatform.wopsdk.crypto.strategies;

import com.wopplatform.wopsdk.crypto.BouncyCastleHolder;
import com.wopplatform.wopsdk.crypto.CryptoException;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 国密报文加密策略：SM4-GCM/NoPadding（BC 承接）。
 * <p>
 * key 16B / IV 12B（CSPRNG）/ tag 128bit；密文 = ciphertext‖tag 尾部拼接（F4）。
 */
public final class Sm4GcmStrategy implements MessageEncryptStrategy {

    public static final Sm4GcmStrategy INSTANCE = new Sm4GcmStrategy();

    private static final String TRANSFORMATION = "SM4/GCM/NoPadding";
    private static final String ALGORITHM = "SM4-GCM";
    private static final int KEY_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Sm4GcmStrategy() {
    }

    @Override
    public CipherResult encrypt(byte[] plain, byte[] key) {
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        return encryptForVector(plain, key, iv);
    }

    /** 固定 IV 加密——<b>黄金向量专用</b>（固定 IV 仅为字节级断言，生产违反不变式 I4）。 */
    CipherResult encryptForVector(byte[] plain, byte[] key, byte[] iv) {
        requireKey(key);
        requireIv(iv);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleHolder.provider());
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(TAG_BITS, iv));
            return new CipherResult(cipher.doFinal(plain), iv);
        } catch (Exception e) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "SM4-GCM 加密失败", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipher, byte[] iv, byte[] key) {
        requireKey(key);
        requireIv(iv);
        try {
            Cipher decryptor = Cipher.getInstance(TRANSFORMATION, BouncyCastleHolder.provider());
            decryptor.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(TAG_BITS, iv));
            return decryptor.doFinal(cipher);
        } catch (Exception e) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "SM4-GCM 解密失败", e);
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
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "SM4 密钥须为 16 字节");
        }
    }

    private static void requireIv(byte[] iv) {
        if (iv == null || iv.length != IV_LENGTH) {
            throw new CryptoException("MESSAGE_ENCRYPT", ALGORITHM, "IV 须为 12 字节");
        }
    }
}
