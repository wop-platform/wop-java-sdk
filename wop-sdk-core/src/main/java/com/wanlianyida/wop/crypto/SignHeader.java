package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

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

    /** 解析结果（不可变，record 等价值语义：equals/hashCode 按全部字段）。 */
    public static final class Parsed {

        /** 算法套件名（如 WOP-RSA3072-SHA256）。 */
        private final String securityReq;

        /** 签名协议版本（v1）。 */
        private final String protocolVersion;

        /** 签名有效期（秒）。 */
        private final long expiredSeconds;

        /** 纳入签名的请求头（已 trim，不可变列表）。 */
        private final List<String> signedHeaders;

        /** 签名 base64url。 */
        private final String signature;

        public Parsed(String securityReq, String protocolVersion, long expiredSeconds,
                      List<String> signedHeaders, String signature) {
            this.securityReq = securityReq;
            this.protocolVersion = protocolVersion;
            this.expiredSeconds = expiredSeconds;
            this.signedHeaders = signedHeaders;
            this.signature = signature;
        }

        /** 算法套件名（如 WOP-RSA3072-SHA256）。 */
        public String securityReq() {
            return securityReq;
        }

        /** 签名协议版本（v1）。 */
        public String protocolVersion() {
            return protocolVersion;
        }

        /** 签名有效期（秒）。 */
        public long expiredSeconds() {
            return expiredSeconds;
        }

        /** 纳入签名的请求头（已 trim，不可变列表）。 */
        public List<String> signedHeaders() {
            return signedHeaders;
        }

        /** 签名 base64url。 */
        public String signature() {
            return signature;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Parsed)) {
                return false;
            }
            Parsed that = (Parsed) o;
            return expiredSeconds == that.expiredSeconds
                    && Objects.equals(securityReq, that.securityReq)
                    && Objects.equals(protocolVersion, that.protocolVersion)
                    && Objects.equals(signedHeaders, that.signedHeaders)
                    && Objects.equals(signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(securityReq, protocolVersion, expiredSeconds, signedHeaders, signature);
        }

        @Override
        public String toString() {
            return "Parsed[securityReq=" + securityReq + ", protocolVersion=" + protocolVersion
                    + ", expiredSeconds=" + expiredSeconds + ", signedHeaders=" + signedHeaders
                    + ", signature=" + signature + "]";
        }
    }

    /** 工具类禁实例化。 */
    private SignHeader() {
    }

    /** 严格解析；格式非法抛 {@link WopError#parse}（协议解析类，10.2）。 */
    public static Parsed parse(String header) {
        if (header == null || header.trim().isEmpty()) {
            throw WopError.parse("缺少 x-wop-sign 请求头");
        }
        String trimmed = header.trim();
        int space = trimmed.indexOf(' ');
        if (space <= 0) {
            throw WopError.parse("x-wop-sign 格式错误：缺少 securityReq 与 authString 的空格分隔");
        }
        String securityReq = trimmed.substring(0, space);
        String[] segments = trimmed.substring(space + 1).split("/", -1);
        if (segments.length != 4) {
            throw WopError.parse("x-wop-sign 格式错误：应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature> 四段（实际 "
                    + segments.length + " 段）");
        }
        if (!PROTOCOL_VERSION.equals(segments[0])) {
            throw WopError.parse("不支持的签名协议版本: " + segments[0] + "（期望 v1）");
        }
        long expiredSeconds = parseExpiredSeconds(segments[1]);
        List<String> signedHeaders = parseSignedHeaders(segments[2]);
        String signature = segments[3];
        if (signature.isEmpty()) {
            throw WopError.parse("x-wop-sign signature 段为空");
        }
        return new Parsed(securityReq, segments[0], expiredSeconds, signedHeaders, signature);
    }

    /** 组装结构化签名头（出向加签用）。 */
    public static String build(String securityReq, long expiredSeconds,
                               List<String> signedHeaders, String signatureB64Url) {
        return securityReq + " " + PROTOCOL_VERSION + "/" + expiredSeconds
                + "/" + String.join(";", signedHeaders) + "/" + signatureB64Url;
    }

    /** 解析并校验 expiredSeconds（须正整数，否则抛明确异常）。 */
    private static long parseExpiredSeconds(String raw) {
        long value;
        try {
            value = Long.parseLong(raw);
        } catch (NumberFormatException e) {
            throw WopError.parse("x-wop-sign expiredSeconds 非数字: '" + raw + "'");
        }
        if (value <= 0) {
            throw WopError.parse("x-wop-sign expiredSeconds 须为正整数: " + value);
        }
        return value;
    }

    /** 解析 signedHeaders 段（分号拆分，空段拒绝，返回不可变列表）。 */
    private static List<String> parseSignedHeaders(String raw) {
        if (raw.isEmpty()) {
            throw WopError.parse("x-wop-sign signedHeaders 段为空");
        }
        String[] names = raw.split(";", -1);
        List<String> result = new ArrayList<>(names.length);
        for (String name : names) {
            String trimmed = name.trim();
            if (trimmed.isEmpty()) {
                throw WopError.parse("x-wop-sign signedHeaders 含空段: '" + raw + "'");
            }
            result.add(trimmed);
        }
        return Collections.unmodifiableList(new ArrayList<>(result));
    }
}
