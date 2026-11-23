package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopSdkException;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F2 canonicalRequest 构造：5 段 '\n' 连接、URLEncoder 语义（空格→%20）、
 * Trimall、ASCII 升序、POST 空查询段保留（与网关 CanonicalRequestBuilder 逐字节对齐）。
 */
class CanonicalRequestTest {

    @Test
    void buildsFiveSegmentsJoinedByNewline() {
        String canonical = CanonicalRequest.build("v1/1800", "POST", "/gateway/order/create", "",
                "x-wop-nonce:abc\nx-wop-timestamp:1758900000000");
        assertEquals("v1/1800\nPOST\n/gateway/order/create\n\nx-wop-nonce:abc\nx-wop-timestamp:1758900000000",
                canonical);
    }

    @Test
    void methodUpperCasedAndNullsToleratedAsEmpty() {
        assertEquals("v1/60\nGET\n/p\n\n", CanonicalRequest.build("v1/60", "get", "/p", "", ""));
        assertEquals("\nPOST\n\n\n", CanonicalRequest.build(null, "POST", null, null, null));
    }

    @Test
    void urlencodeEncodesSpaceAsPercent20() {
        // Java URLEncoder 语义：空格 → '+' 需替换回 %20；'/' 与 ';' 等保留字也转义
        assertEquals("a%20b", CanonicalRequest.urlencode("a b"));
        assertEquals("sha-256%204cf7ab3b", CanonicalRequest.urlencode("sha-256 4cf7ab3b"));
        assertEquals("L2%3Bdek%3Dabc", CanonicalRequest.urlencode("L2;dek=abc"));
        assertEquals("%2Fpath", CanonicalRequest.urlencode("/path"));
        // 中文与 em-dash UTF-8 转义
        assertEquals("%E8%B7%A8%E8%AF%AD%E8%A8%80", CanonicalRequest.urlencode("跨语言"));
        assertEquals("", CanonicalRequest.urlencode(null));
        assertEquals("", CanonicalRequest.urlencode(""));
    }

    @Test
    void urlencodeWithBogusCharsetFailsAsSdkException() {
        // charset 参数化 seam（Java 8 无 URLEncoder.encode(String, Charset) 重载）：
        // 非法字符集名 → WopSdkException，而非漏出 Checked 的 UnsupportedEncodingException
        WopSdkException ex = assertThrows(WopSdkException.class,
                () -> CanonicalRequest.urlencode("x", "BOGUS"));
        assertTrue(ex.getMessage().contains("BOGUS"), ex.getMessage());
    }

    @Test
    void trimallCollapsesWhitespace() {
        assertEquals("a b", CanonicalRequest.trimall("  a \t b  "));
        assertEquals("", CanonicalRequest.trimall(null));
        assertEquals("x", CanonicalRequest.trimall("x"));
    }

    @Test
    void trimallFoldsOnlyAsciiRegexWhitespace() {
        assertEquals("a b c", CanonicalRequest.trimall("a\n\r\f\u000Bb\tc"));
        assertEquals("a\u0000b", CanonicalRequest.trimall("a\u0000b"));
        assertEquals("a\u0001 b", CanonicalRequest.trimall("a\u0001   b"));
        assertEquals("a\u0007 b", CanonicalRequest.trimall(" a\u0007  b "));
        assertEquals("a b", CanonicalRequest.trimall(" a  b\u0007 "));
        assertEquals("", CanonicalRequest.trimall(""));
        assertEquals("", CanonicalRequest.trimall(" \t\n\r\f\u000B "));
        assertEquals("a b", CanonicalRequest.trimall("a         b"));
    }

    @Test
    void trimallIsEquivalentToLegacyRegexOracle() {
        String[][] cases = {
                {"", ""}, {" ", ""}, {"   ", ""}, {"x", "x"}, {" x ", "x"},
                {"a b", "a b"}, {"a  b", "a b"}, {"a\tb", "a b"}, {"a\r\nb", "a b"},
                {"  a \t b  ", "a b"}, {"a\u0000b", "a\u0000b"}, {"a\u0001\tb", "a\u0001 b"},
                {"a\u000Bb", "a b"}, {"a\fb", "a b"}, {"\ta\tb\t", "a b"},
                {"a\u00A0b", "a\u00A0b"}, {"跨 语言", "跨 语言"},
                {"a b c d e", "a b c d e"}, {"a     b     c", "a b c"},
        };
        for (String[] c : cases) {
            assertEquals(oracle(c[0]), CanonicalRequest.trimall(c[0]), "输入: " + escape(c[0]));
            assertEquals(c[1], CanonicalRequest.trimall(c[0]), "期望: " + escape(c[0]));
        }
    }

    private static String oracle(String text) {
        return text == null ? "" : text.trim().replaceAll("\\s+", " ");
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            sb.append(c < 0x20 || c > 0x7E ? String.format("\\u%04X", (int) c) : String.valueOf(c));
        }
        return sb.toString();
    }

    @Test
    void canonicalHeadersSortByNameAsciiAndEncodeValues() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Wop-Timestamp", " 1758900000000 ");
        headers.put("x-wop-nonce", "ab c");
        headers.put("X-WOP-CONTENT-DIGEST", "sha-256 4cf7");
        assertEquals("x-wop-content-digest:sha-256%204cf7\n"
                        + "x-wop-nonce:ab%20c\n"
                        + "x-wop-timestamp:1758900000000",
                CanonicalRequest.canonicalHeaders(headers));
    }

    @Test
    void canonicalHeadersEmptyAndNullMaps() {
        assertEquals("", CanonicalRequest.canonicalHeaders(null));
        assertEquals("", CanonicalRequest.canonicalHeaders(new LinkedHashMap<String, String>()));
    }

    @Test
    void goldenFullCanonicalMatchesGatewayShape() {
        // 与网关侧拼装逐字节对齐的完整样例（含空 query 段）
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("x-wop-appkey", "app_001");
        headers.put("x-wop-nonce", "n0nce123");
        headers.put("x-wop-timestamp", "1758900000000");
        headers.put("x-wop-content-digest",
                "sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf");
        String canonical = CanonicalRequest.build("v1/1800", "POST", "/gateway/open/api", "",
                CanonicalRequest.canonicalHeaders(headers));
        assertEquals("v1/1800\n"
                + "POST\n"
                + "/gateway/open/api\n"
                + "\n"
                + "x-wop-appkey:app_001\n"
                + "x-wop-content-digest:sha-256%2023592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf\n"
                + "x-wop-nonce:n0nce123\n"
                + "x-wop-timestamp:1758900000000", canonical);
    }
}
