package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * 国际签名策略：SHA256withRSA（PKCS#1 v1.5）。
 * <p>
 * RSA PKCS#1 v1.5 签名确定性——同密钥同消息字节级一致（黄金向量直接锚定）。
 * userId 对 RSA 无意义（D14 仅 SM2 需要），实现忽略入参。
 */
public final class RsaPkcs1SignatureStrategy implements SignatureStrategy {

    public static final RsaPkcs1SignatureStrategy INSTANCE = new RsaPkcs1SignatureStrategy();

    private static final String ALGORITHM = "SHA256withRSA";

    /** 无状态单例，私有构造。 */
    private RsaPkcs1SignatureStrategy() {
    }

    /** 加签（PKCS#1 v1.5 确定性:同密钥同消息字节级一致；userId 忽略）。 */
    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey, byte[] userId) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        } catch (Exception e) {
            throw new CryptoException("SIGNATURE", ALGORITHM, "RSA 签名执行失败", e);
        }
    }

    /** 验签（userId 忽略）。 */
    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey, byte[] userId) {
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new CryptoException("SIGNATURE", ALGORITHM, "RSA 验签执行失败", e);
        }
    }

    /** 线上算法名 SHA256withRSA。 */
    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
