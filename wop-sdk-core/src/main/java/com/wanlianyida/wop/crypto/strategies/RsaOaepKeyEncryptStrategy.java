package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class RsaOaepKeyEncryptStrategy implements KeyEncryptStrategy {

    public static final RsaOaepKeyEncryptStrategy INSTANCE = new RsaOaepKeyEncryptStrategy();

    private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final String ALGORITHM = "RSA-OAEP(SHA-256/MGF1-SHA-256)";

    private static final OAEPParameterSpec OAEP =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private RsaOaepKeyEncryptStrategy() {
    }

    /** 包装（OAEP 随机源走新建 SecureRandom）。 */
    @Override
    public byte[] encrypt(byte[] plainKey, PublicKey publicKey) {
        return encrypt(plainKey, publicKey, new SecureRandom());
    }

    /** OAEP seed 取自注入源（确定性钩子；JCA 以 SecureRandom 供给 OAEP 填充随机）。 */
    @Override
    public byte[] encrypt(byte[] plainKey, PublicKey publicKey, SecureRandom random) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP, random);
            return cipher.doFinal(plainKey);
        } catch (Exception e) {
            throw new CryptoException("KEY_ENCRYPT", ALGORITHM, "RSA-OAEP 包装失败", e);
        }
    }

    /** 解包（OAEP 参数显式钉死 SHA-256 / MGF1-SHA-256，不依赖 JCA 默认）。 */
    @Override
    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP);
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new CryptoException("KEY_ENCRYPT", ALGORITHM, "RSA-OAEP 解包失败", e);
        }
    }

    /** 线上算法名 RSA-OAEP（SHA-256/MGF1-SHA-256）。 */
    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
