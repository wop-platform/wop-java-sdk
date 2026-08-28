package com.wopplatform.wopsdk.crypto;

import com.wopplatform.wopsdk.WopSdkException;

import java.util.Arrays;

/**
 * F5 DEK 载荷：{@code alg$base64url(key)$base64url(iv)}（crypto spec §6.1）。
 * {@code $} 不在 base64url 字母表中，分隔符无碰撞；key/iv 解码走严格 base64url。
 */
public record DekPayload(String alg, byte[] key, byte[] iv) {

    /** 编码为载荷明文串。 */
    public static String encode(DekPayload payload) {
        if (payload == null || payload.alg == null || payload.alg.isBlank()
                || payload.key == null || payload.key.length == 0
                || payload.iv == null || payload.iv.length == 0) {
            throw new WopSdkException("DEK 载荷字段不完整");
        }
        return payload.alg + "$" + Codec.b64UrlEncode(payload.key) + "$" + Codec.b64UrlEncode(payload.iv);
    }

    /** 严格解码：恰三段，alg 非空，key/iv 合法 base64url 无填充。 */
    public static DekPayload decode(String payloadText) {
        if (payloadText == null || payloadText.isEmpty()) {
            throw new WopSdkException("DEK 载荷为空");
        }
        String[] segments = payloadText.split("\\$", -1);
        if (segments.length != 3) {
            throw new WopSdkException("DEK 载荷须为 alg$key$iv 三段（实际 " + segments.length + " 段）");
        }
        if (segments[0].isBlank()) {
            throw new WopSdkException("DEK 载荷 alg 段为空");
        }
        try {
            return new DekPayload(segments[0], Codec.b64UrlDecode(segments[1]), Codec.b64UrlDecode(segments[2]));
        } catch (IllegalArgumentException e) {
            throw new WopSdkException("DEK 载荷 key/iv 段非合法 base64url 无填充: " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        return "DekPayload[alg=" + alg + ", key=" + Arrays.toString(new byte[0]) + "-hidden]";
    }
}
