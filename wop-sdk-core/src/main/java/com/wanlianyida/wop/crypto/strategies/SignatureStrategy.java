package com.wanlianyida.wop.crypto.strategies;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureStrategy {

    byte[] sign(byte[] data, PrivateKey privateKey, byte[] userId);

    boolean verify(byte[] data, byte[] signature, PublicKey publicKey, byte[] userId);

    String algorithmName();
}
