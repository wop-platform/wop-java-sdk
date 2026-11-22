package com.wanlianyida.wop.crypto.strategies;

import java.util.Objects;

/**
 * 对称加密结果：密文（含 GCM tag 尾拼，F4）与 IV 同生同传。
 * <p>
 * 不可变值对象（record 等价语义：equals/hashCode 按全部字段，数组字段引用比较）。
 */
public final class CipherResult {

    /** 密文（含 GCM tag 尾拼）。 */
    private final byte[] cipher;

    /** IV。 */
    private final byte[] iv;

    public CipherResult(byte[] cipher, byte[] iv) {
        this.cipher = cipher;
        this.iv = iv;
    }

    /** 密文（含 GCM tag 尾拼）。 */
    public byte[] cipher() {
        return cipher;
    }

    /** IV。 */
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
