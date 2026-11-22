package com.wanlianyida.wop.crypto.strategies;

public interface MessageEncryptStrategy {

    CipherResult encrypt(byte[] plain, byte[] key);

    default CipherResult encrypt(byte[] plain, byte[] key, java.security.SecureRandom random) {
        return encrypt(plain, key);
    }

    byte[] decrypt(byte[] cipher, byte[] iv, byte[] key);

    String algorithmName();

    int keyLength();

    int ivLength();
}
