package com.wanlianyida.wop.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 线上编码统一入口（F7/D10/D2）：
 * <ul>
 *   <li>二进制线上编码 = base64url <b>无填充严格模式</b>：拒收含 {@code =}/{@code +}/{@code /}、
 *       长度 mod 4 == 1 的输入，以及<b>尾随位非零</b>的非规范编码（RFC 4648 §3.5，
 *       语义同 Go base64.RawURLEncoding.Strict()；JDK 内建解码器对尾随位宽容，故须前置校验）</li>
 *   <li>十六进制统一<b>小写</b>（.NET BitConverter 大写带连字符是经典翻车点，此处钉死）</li>
 * </ul>
 */
public final class Codec {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Codec() {
    }

    /** base64url 无填充编码。 */
    public static String b64UrlEncode(byte[] data) {
        return B64URL.encodeToString(data);
    }

    /**
     * base64url 无填充<b>严格</b>解码：拒收字母表外的任何字符（含 {@code =}）、
     * 长度 mod 4 == 1、尾随位非零的非规范编码（RFC 4648 §3.5）。
     */
    public static byte[] b64UrlDecode(String text) {
        if (text == null) {
            throw new IllegalArgumentException("base64url 输入为 null");
        }
        int length = text.length();
        if (length % 4 == 1) {
            throw new IllegalArgumentException("base64url 长度非法（mod 4 == 1）: " + length);
        }
        for (int i = 0; i < length; i++) {
            char c = text.charAt(i);
            if (!isB64UrlChar(c)) {
                throw new IllegalArgumentException("base64url 含非法字符 '" + c + "'（序号 " + i + "）");
            }
        }
        int rem = length % 4;
        if (rem == 2 || rem == 3) {
            // 尾组最后一字符的低 (rem==2 ? 4 : 2) 位是丢弃位，非零即非规范编码（JDK 解码器宽容，须显式拒收）
            int mask = rem == 2 ? 0xF : 0x3;
            if ((b64UrlCharIndex(text.charAt(length - 1)) & mask) != 0) {
                throw new IllegalArgumentException(
                        "base64url 尾随位非零（非规范编码，RFC 4648 §3.5）: '" + text + "'");
            }
        }
        return B64URL_DEC.decode(text);
    }

    /** 小写十六进制（D2/D10）。 */
    public static String hexLower(byte[] data) {
        if (data == null) {
            return "";
        }
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** 是否为恰好 64 位小写 hex（摘要头 hex 段格式校验，D2）。 */
    public static boolean isLowerHex64(String text) {
        if (text == null || text.length() != 64) {
            return false;
        }
        for (int i = 0; i < 64; i++) {
            char c = text.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                return false;
            }
        }
        return true;
    }

    /** UTF-8 字节。 */
    public static byte[] utf8(String text) {
        return text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
    }

    /** 字节拼接（避免 List&lt;byte[]&gt; 样板）。 */
    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static boolean isB64UrlChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    }

    /** 字母表字符 → 6 位值（A-Z=0-25, a-z=26-51, 0-9=52-61, '-'=62, '_'=63）；调用前须已过 {@link #isB64UrlChar}。 */
    private static int b64UrlCharIndex(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';              // 0-25
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;         // 26-51
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;         // 52-61
        }
        return c == '-' ? 62 : 63;       // '-' / '_'（调用前已过字母表校验）
    }
}
