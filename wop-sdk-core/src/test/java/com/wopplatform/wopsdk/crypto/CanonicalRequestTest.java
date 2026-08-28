package com.wopplatform.wopsdk.crypto;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
    void trimallCollapsesWhitespace() {
        assertEquals("a b", CanonicalRequest.trimall("  a \t b  "));
        assertEquals("", CanonicalRequest.trimall(null));
        assertEquals("x", CanonicalRequest.trimall("x"));
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
        assertEquals("", CanonicalRequest.canonicalHeaders(Map.of()));
    }

    @Test
    void goldenFullCanonicalMatchesGatewayShape() {
        // 与网关侧拼装逐字节对齐的完整样例（含空 query 段）
        Map<String, String> headers = Map.of(
                "x-wop-appkey", "app_001",
                "x-wop-nonce", "n0nce123",
                "x-wop-timestamp", "1758900000000",
                "x-wop-content-digest", "sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf");
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
