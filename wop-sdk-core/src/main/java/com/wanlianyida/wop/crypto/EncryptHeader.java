package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import java.util.Objects;

public final class EncryptHeader {

    public static final class Parsed {

        private final String level;

        /** DEK 载荷 base64url；L0 时为 null。 */
        private final String dek;

        public Parsed(String level, String dek) {
            this.level = level;
            this.dek = dek;
        }

        public String level() {
            return level;
        }

        /** DEK 载荷 base64url；L0 时为 null。 */
        public String dek() {
            return dek;
        }

        public boolean isEncrypted() {
            return "L2".equals(level);
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
            return Objects.equals(level, that.level) && Objects.equals(dek, that.dek);
        }

        @Override
        public int hashCode() {
            return Objects.hash(level, dek);
        }

        @Override
        public String toString() {
            return "Parsed[level=" + level + ", dek=" + dek + "]";
        }
    }

    private EncryptHeader() {
    }

    /** 头缺席（null）等价 L0；其余严格解析。 */
    public static Parsed parse(String header) {
        if (header == null) {
            return new Parsed("L0", null);
        }
        int semicolon = header.indexOf(';');
        String level = semicolon < 0 ? header : header.substring(0, semicolon);
        if (!"L0".equals(level) && !"L2".equals(level)) {
            throw WopError.parse("x-wop-encrypt 加密指令解析失败：level 仅支持 L0/L2，实际 '" + level + "'");
        }
        if (semicolon < 0) {
            if ("L2".equals(level)) {
                throw WopError.parse("L2 加密指令缺少 dek 段");
            }
            return new Parsed("L0", null);
        }
        String param = header.substring(semicolon + 1);
        if ("L0".equals(level)) {
            throw WopError.parse("x-wop-encrypt L0 不携带参数: '" + header + "'");
        }
        if (!param.startsWith("dek=") || param.length() <= 4) {
            throw WopError.parse("L2 加密指令缺少 dek 段: '" + header + "'");
        }
        String dek = param.substring(4);
        try {
            Codec.b64UrlDecode(dek);
        } catch (IllegalArgumentException e) {
            throw WopError.parse("x-wop-encrypt dek 段非合法 base64url 无填充: " + e.getMessage(), e);
        }
        return new Parsed("L2", dek);
    }

    public static String buildL2(String dekB64Url) {
        return "L2;dek=" + dekB64Url;
    }
}
