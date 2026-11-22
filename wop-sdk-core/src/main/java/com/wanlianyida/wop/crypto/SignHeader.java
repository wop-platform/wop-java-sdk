package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class SignHeader {

    public static final String PROTOCOL_VERSION = "v1";

    public static final class Parsed {

        private final String securityReq;

        private final String protocolVersion;

        private final long expiredSeconds;

        private final List<String> signedHeaders;

        private final String signature;

        public Parsed(String securityReq, String protocolVersion, long expiredSeconds,
                      List<String> signedHeaders, String signature) {
            this.securityReq = securityReq;
            this.protocolVersion = protocolVersion;
            this.expiredSeconds = expiredSeconds;
            this.signedHeaders = signedHeaders;
            this.signature = signature;
        }

        public String securityReq() {
            return securityReq;
        }

        public String protocolVersion() {
            return protocolVersion;
        }

        public long expiredSeconds() {
            return expiredSeconds;
        }

        public List<String> signedHeaders() {
            return signedHeaders;
        }

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

    private SignHeader() {
    }

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
            throw WopError.parse("x-wop-sign expiredSeconds 非数字: '" + raw + "'");
        }
        if (value <= 0) {
            throw WopError.parse("x-wop-sign expiredSeconds 须为正整数: " + value);
        }
        return value;
    }

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
