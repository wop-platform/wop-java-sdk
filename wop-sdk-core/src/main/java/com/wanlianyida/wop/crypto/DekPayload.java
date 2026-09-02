package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import java.util.Arrays;
import java.util.Objects;

/**
 * F5 DEK 载荷：{@code alg$base64url(key)$base64url(iv)}（crypto spec §6.1）。
 * {@code $} 不在 base64url 字母表中，分隔符无碰撞；key/iv 解码走严格 base64url。
 * <p>
 * 不可变值对象（record 等价语义：equals/hashCode 按全部字段，数组字段引用比较）。
 */
public final class DekPayload {

    /** 算法族标识（RSA-OAEP-3072 / SM2）。 */
    private final String alg;

    /** 内容加密密钥（DEK）。 */
    private final byte[] key;

    /** IV。 */
    private final byte[] iv;

    public DekPayload(String alg, byte[] key, byte[] iv) {
        this.alg = alg;
        this.key = key;
        this.iv = iv;
    }

    /** 算法族标识（RSA-OAEP-3072 / SM2）。 */
    public String alg() {
        return alg;
    }

    /** 内容加密密钥（DEK）。 */
    public byte[] key() {
        return key;
    }

    /** IV。 */
    public byte[] iv() {
        return iv;
    }

    /** 编码为载荷明文串。 */
    public static String encode(DekPayload payload) {
        if (payload == null || payload.alg == null || payload.alg.trim().isEmpty()
                || payload.key == null || payload.key.length == 0
                || payload.iv == null || payload.iv.length == 0) {
            throw WopError.parse("DEK 载荷字段不完整");
        }
        return payload.alg + "$" + Codec.b64UrlEncode(payload.key) + "$" + Codec.b64UrlEncode(payload.iv);
    }

    /** 严格解码：恰三段，alg 非空，key/iv 合法 base64url 无填充。 */
    public static DekPayload decode(String payloadText) {
        if (payloadText == null || payloadText.isEmpty()) {
            throw WopError.parse("DEK 载荷为空");
        }
        String[] segments = payloadText.split("\\$", -1);
        if (segments.length != 3) {
            throw WopError.parse("DEK 载荷须为 alg$key$iv 三段（实际 " + segments.length + " 段）");
        }
        if (segments[0].trim().isEmpty()) {
            throw WopError.parse("DEK 载荷 alg 段为空");
        }
        try {
            return new DekPayload(segments[0], Codec.b64UrlDecode(segments[1]), Codec.b64UrlDecode(segments[2]));
        } catch (IllegalArgumentException e) {
            throw WopError.parse("DEK 载荷 key/iv 段非合法 base64url 无填充: " + e.getMessage(), e);
        }
    }

    /** 调试串（key 恒隐去，防泄漏）。 */
    @Override
    public String toString() {
        return "DekPayload[alg=" + alg + ", key=" + Arrays.toString(new byte[0]) + "-hidden]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DekPayload)) {
            return false;
        }
        DekPayload that = (DekPayload) o;
        return Objects.equals(alg, that.alg) && Objects.equals(key, that.key)
                && Objects.equals(iv, that.iv);
    }

    @Override
    public int hashCode() {
        return Objects.hash(alg, key, iv);
    }
}
