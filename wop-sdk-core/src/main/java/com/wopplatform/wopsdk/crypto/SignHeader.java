package com.wopplatform.wopsdk.crypto;

import com.wopplatform.wopsdk.WopSdkException;

import java.util.ArrayList;
import java.util.List;

/**
 * F3 结构化签名头 x-wop-sign 编解码。
 * <p>
 * 格式（空格分隔两段）：
 * <pre>{@code <securityReq> <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature>}</pre>
 * 示例：{@code WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-nonce;.../pOVoj1mI...}。
 * 签名为 base64url（无 '/'），split -1 全量拆分后要求恰 4 段。
 */
public final class SignHeader {

    /** 签名协议版本（唯一支持）。 */
    public static final String PROTOCOL_VERSION = "v1";

    /** 解析结果（不可变）。 */
    public record Parsed(String securityReq, String protocolVersion, long expiredSeconds,
                         List<String> signedHeaders, String signature) {
    }

    private SignHeader() {
    }

    /** 严格解析；格式非法抛明确异常（解析类，10.2）。 */
    public static Parsed parse(String header) {
        if (header == null || header.isBlank()) {
            throw new WopSdkException("缺少 x-wop-sign 请求头");
        }
        String trimmed = header.trim();
        int space = trimmed.indexOf(' ');
        if (space <= 0) {
            throw new WopSdkException("x-wop-sign 格式错误：缺少 securityReq 与 authString 的空格分隔");
        }
        String securityReq = trimmed.substring(0, space);
        String[] segments = trimmed.substring(space + 1).split("/", -1);
        if (segments.length != 4) {
            throw new WopSdkException("x-wop-sign 格式错误：应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature> 四段（实际 "
                    + segments.length + " 段）");
        }
        if (!PROTOCOL_VERSION.equals(segments[0])) {
            throw new WopSdkException("不支持的签名协议版本: " + segments[0] + "（期望 v1）");
        }
        long expiredSeconds = parseExpiredSeconds(segments[1]);
        List<String> signedHeaders = parseSignedHeaders(segments[2]);
        String signature = segments[3];
        if (signature.isEmpty()) {
            throw new WopSdkException("x-wop-sign signature 段为空");
        }
        return new Parsed(securityReq, segments[0], expiredSeconds, signedHeaders, signature);
    }

    /** 组装结构化签名头（出向加签用）。 */
    public static String build(String securityReq, long expiredSeconds,
                               List<String> signedHeaders, String signatureB64Url) {
        return securityReq + " " + PROTOCOL_VERSION + "/" + expiredSeconds
                + "/" + String.join(";", signedHeaders) + "/" + signatureB64Url;
    }

    private static long parseExpiredSeconds(String raw) {
        long value;
        try {
            value = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw new WopSdkException("x-wop-sign expiredSeconds 非数字: '" + raw + "'");
        }
        if (value <= 0) {
            throw new WopSdkException("x-wop-sign expiredSeconds 须为正整数: " + value);
        }
        return value;
    }

    private static List<String> parseSignedHeaders(String raw) {
        if (raw.isEmpty()) {
            throw new WopSdkException("x-wop-sign signedHeaders 段为空");
        }
        String[] names = raw.split(";", -1);
        List<String> result = new ArrayList<>(names.length);
        for (String name : names) {
            String trimmed = name.trim();
            if (trimmed.isEmpty()) {
                throw new WopSdkException("x-wop-sign signedHeaders 含空段: '" + raw + "'");
            }
            result.add(trimmed);
        }
        return List.copyOf(result);
    }
}
