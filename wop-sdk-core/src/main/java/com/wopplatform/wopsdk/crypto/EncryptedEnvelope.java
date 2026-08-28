package com.wopplatform.wopsdk.crypto;

import com.wopplatform.wopsdk.WopSdkException;

import java.nio.charset.StandardCharsets;

/**
 * L2 线上密文信封 {@code {"encrypted":"<base64url(ciphertext||tag)>"}} 的严格编解码
 * （固定形态，零第三方 JSON 依赖；额外字段/转义/尾随内容一律拒绝）。
 */
public final class EncryptedEnvelope {

    private static final String PREFIX = "{\"encrypted\":\"";
    private static final String SUFFIX = "\"}";

    private EncryptedEnvelope() {
    }

    /** 包装密文为线上信封字节。 */
    public static byte[] wrap(String cipherB64Url) {
        return (PREFIX + cipherB64Url + SUFFIX).getBytes(StandardCharsets.UTF_8);
    }

    /** 提取并严格解码密文；形态非法抛明确异常（公开协议知识，解析类）。 */
    public static byte[] cipherOf(byte[] wireBody) {
        if (wireBody == null || wireBody.length == 0) {
            throw new WopSdkException("L2 密文载体为空");
        }
        String text = new String(wireBody, StandardCharsets.UTF_8).trim();
        if (!text.startsWith(PREFIX) || !text.endsWith(SUFFIX) || text.length() <= PREFIX.length() + SUFFIX.length()) {
            throw new WopSdkException("L2 密文载体须为 {\"encrypted\":\"<base64url>\"}");
        }
        String cipherB64u = text.substring(PREFIX.length(), text.length() - SUFFIX.length());
        try {
            return Codec.b64UrlDecode(cipherB64u);
        } catch (IllegalArgumentException e) {
            throw new WopSdkException("L2 密文载体 encrypted 段非合法 base64url 无填充: " + e.getMessage(), e);
        }
    }
}
