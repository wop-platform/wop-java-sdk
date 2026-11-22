package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class RsaPkcs1SignatureStrategy implements SignatureStrategy {

    public static final RsaPkcs1SignatureStrategy INSTANCE = new RsaPkcs1SignatureStrategy();

    private static final String ALGORITHM = "SHA256withRSA";

    private RsaPkcs1SignatureStrategy() {
    }

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

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}
