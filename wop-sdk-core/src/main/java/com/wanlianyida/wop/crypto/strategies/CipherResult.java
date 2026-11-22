package com.wanlianyida.wop.crypto.strategies;

import java.util.Objects;

public final class CipherResult {

    /** 密文（含 GCM tag 尾拼）。 */
    private final byte[] cipher;

    private final byte[] iv;

    public CipherResult(byte[] cipher, byte[] iv) {
        this.cipher = cipher;
        this.iv = iv;
    }

    /** 密文（含 GCM tag 尾拼）。 */
    public byte[] cipher() {
        return cipher;
    }

    public byte[] iv() {
        return iv;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CipherResult)) {
            return false;
        }
        CipherResult that = (CipherResult) o;
        return Objects.equals(cipher, that.cipher) && Objects.equals(iv, that.iv);
    }

    @Override
    public int hashCode() {
        return Objects.hash(cipher, iv);
    }

    @Override
    public String toString() {
        return "CipherResult[cipher=" + cipher + ", iv=" + iv + "]";
    }
}
