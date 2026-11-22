package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import java.util.Objects;

public final class ContentDigest {

    public static final class Parsed {

        private final String label;

        private final String hex;

        public Parsed(String label, String hex) {
            this.label = label;
            this.hex = hex;
        }

        public String label() {
            return label;
        }

        public String hex() {
            return hex;
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
            return Objects.equals(label, that.label) && Objects.equals(hex, that.hex);
        }

        @Override
        public int hashCode() {
            return Objects.hash(label, hex);
        }

        @Override
        public String toString() {
            return "Parsed[label=" + label + ", hex=" + hex + "]";
        }
    }

    private ContentDigest() {
    }

    public static String build(AlgorithmSuite suite, byte[] wireBody) {
        if (wireBody == null || wireBody.length == 0) {
            return null;
        }
        return suite.digestLabel() + " " + Codec.hexLower(suite.digest().digest(wireBody));
    }

    /** 严格解析：标签 = 套件期望标签（I5），恰一空格，64 位小写 hex；violation 抛 {@link WopError#parse}。 */
    public static Parsed parse(String headerValue, AlgorithmSuite suite) {
        if (headerValue == null || headerValue.isEmpty()) {
            throw WopError.parse("x-wop-content-digest 为空");
        }
        int space = headerValue.indexOf(' ');
        if (space < 0) {
            throw WopError.parse("x-wop-content-digest 缺少算法标签与 hex 的空格分隔: '" + headerValue + "'");
        }
        if (space != headerValue.lastIndexOf(' ')) {
            throw WopError.parse("x-wop-content-digest 必须恰好一个空格（D2）: '" + headerValue + "'");
        }
        String label = headerValue.substring(0, space);
        String hex = headerValue.substring(space + 1);
        if (!label.equals(suite.digestLabel())) {
            throw WopError.parse("x-wop-content-digest 标签 '" + label + "' 与套件族不符（期望 "
                    + suite.digestLabel() + "，跨族拒绝 I5）");
        }
        if (!Codec.isLowerHex64(hex)) {
            throw WopError.parse("x-wop-content-digest hex 段须为 64 位小写十六进制（D2/F5）: '" + hex + "'");
        }
        return new Parsed(label, hex);
    }
}
