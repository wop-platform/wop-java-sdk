package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ConfigJsonParser 存活变异体定点补测（D12 PIT）：
 * \\u 转义 hex 边界位（a/f/A/F）、正整数上限 Integer.MAX_VALUE、skipValue/expect/
 * requireCommaOrClose/ensureConsumed 的前导空白容忍、未闭合转义恰在 EOF 边界。
 */
class ConfigJsonParserBoundaryTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static String base() {
        return "{\"appKey\":\"app_001\""
                + ",\"suite\":\"WOP-RSA3072-SHA256\""
                + ",\"merchantPrivateKey\":\"" + RSA_PRIV + "\""
                + ",\"platformPublicKey\":\"" + RSA_PUB + "\""
                + ",\"serverRoot\":\"https://gw.example.com/gateway\"}";
    }

    private static String withField(String extra) {
        String b = base();
        return b.substring(0, b.length() - 1) + "," + extra + "}";
    }

    private static String withAppKey(String literal) {
        return base().replace("\"appKey\":\"app_001\"", "\"appKey\":\"" + literal + "\"");
    }

    private static WopError parseError(String json) {
        return assertThrows(WopError.class, () -> ConfigJsonParser.parse(json));
    }

    @Test
    void unicodeHexBoundaryDigitsBothCasesAccepted() {
        // \\u 转义 hex 位边界：小写 a/f 与大写 A/F 各自命中原分支（'¯' = U+00AF）
        assertEquals("¯¯", ConfigJsonParser.parse(withAppKey("\\u00af\\u00AF")).appKey());
    }

    @Test
    void intMaxValueAcceptedForHttpClientNumbers() {
        // 正整数上限值原样通过（数值越界守卫只拦 > MAX；窄化返回须保留原值）
        WopSdkConfig cfg = ConfigJsonParser.parse(withField(
                "\"httpClient\":{\"connectTimeout\":2147483647,\"maxRetryCount\":2147483647}"));
        assertEquals(2147483647, cfg.httpClient().connectTimeout());
        assertEquals(2147483647, cfg.httpClient().maxRetryCount());
    }

    @Test
    void skipValueToleratesWhitespaceBeforeObjectValue() {
        // 未知字段对象值带前导空白：skipValue 先吞空白再识别 '{'
        assertEquals("app_001", ConfigJsonParser.parse(withField("\"x\": {\"a\":1}")).appKey());
    }

    @Test
    void tryConsumeToleratesWhitespaceBetweenCommaAndRootClose() {
        // 逗号后到收尾 '}' 前的空白由循环顶部 tryConsume 的 skipWhitespace 消费；
        // 移除该调用会把空白当作下一键起点导致解析失败
        assertEquals("app_001", ConfigJsonParser.parse(withField("\"x\":\"a\", ")).appKey());
    }

    @Test
    void skipArrayMissingCommaRejected() {
        // 跳过数组内元素缺逗号：requireCommaOrClose 报"期望 ','"
        assertTrue(parseError(withField("\"x\": [\"a\" \"b\"]")).getMessage().contains("期望 ','"));
    }

    @Test
    void whitespaceBeforeColonTolerated() {
        // 成员冒号前空白：expect 先吞空白再比对 ':'
        assertEquals("app_001", ConfigJsonParser.parse(base().replace("\"appKey\":", "\"appKey\" :")).appKey());
    }

    @Test
    void whitespaceBeforeRootCloseTolerated() {
        // 末成员后、根右括号前的空白：requireCommaOrClose 吞空白后走 '}' 提前返回
        assertEquals("app_001", ConfigJsonParser.parse(withField("\"x\":\"a\" ")).appKey());
    }

    @Test
    void unicodeWhitespaceTailTolerated() {
        // U+2000 是 Character.isWhitespace 但超出 trim(<=0x20) 范围：ensureConsumed 吞掉后成功
        assertEquals("app_001", ConfigJsonParser.parse(base() + " ").appKey());
    }

    @Test
    void unicodeEscapeExactEofBoundaryNotShortRead() {
        // \\u 后恰有 4 个 hex 位且 EOF：须正常读出转义并以"字符串未闭合"收尾，
        // 而非误报"\\u 转义不完整"（pos+4 == length 的边界）
        assertTrue(parseError(unterminated("\"x\":\"\\u0041")).getMessage().contains("字符串未闭合"));
    }

    private static String unterminated(String extra) {
        String b = base();
        return b.substring(0, b.length() - 1) + "," + extra;
    }
}
