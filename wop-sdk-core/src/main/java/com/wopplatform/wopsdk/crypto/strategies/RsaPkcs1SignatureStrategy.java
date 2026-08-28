package com.wopplatform.wopsdk.crypto.strategies;

import com.wopplatform.wopsdk.crypto.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * 国际签名策略：SHA256withRSA（PKCS#1 v1.5）。
 * <p>
 * RSA PKCS#1 v1.5 签名确定性——同密钥同消息字节级一致（黄金向量直接锚定）。
 */
public final class RsaPkcs1SignatureStrategy implements SignatureStrategy {

    public static final RsaPkcs1SignatureStrategy INSTANCE = new RsaPkcs1SignatureStrategy();

    private static final String ALGORITHM = "SHA256withRSA";

    private RsaPkcs1SignatureStrategy() {
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(data);
            return signer.sign();
        } catch (Exception e) {
            throw new CryptoException("SIGNATURE", ALGORITHM, "RSA 签名执行失败", e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new CryptoException("SIGNATURE", ALGORITHM, "RSA 验签执行失败", e);
        }
    }

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
