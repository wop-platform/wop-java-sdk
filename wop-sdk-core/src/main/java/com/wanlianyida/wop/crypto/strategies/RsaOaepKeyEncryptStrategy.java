package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * 国际密钥加密策略：RSA-OAEP <b>显式参数化</b>（F2/D10 头号跨语言漂移源）。
 * <p>
 * OAEP 摘要 SHA-256，MGF1 摘要<b>显式钉死 SHA-256</b>（JCA 串
 * {@code OAEPWithSHA-256AndMGF1Padding} 的 MGF1 默认是 SHA-1，禁止依赖默认值），label 为空。
 */
public final class RsaOaepKeyEncryptStrategy implements KeyEncryptStrategy {

    public static final RsaOaepKeyEncryptStrategy INSTANCE = new RsaOaepKeyEncryptStrategy();

    private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final String ALGORITHM = "RSA-OAEP(SHA-256/MGF1-SHA-256)";

    private static final OAEPParameterSpec OAEP =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private RsaOaepKeyEncryptStrategy() {
    }

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

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
