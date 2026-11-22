package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ConfigJsonParser 边界与错误消息全覆盖（K8/K21）：null/空/BOM、根类型、
 * 尾随内容、未知字段全类型忽略、NaN/Infinity 拒绝、数字与转义校验、重复键硬错。
 */
class ConfigJsonParserEdgeTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    /** 最小完整合法配置（成功解析必经 validateAndNormalize）。 */
    private static String base() {
        return "{\"appKey\":\"app_001\""
                + ",\"suite\":\"WOP-RSA3072-SHA256\""
                + ",\"merchantPrivateKey\":\"" + RSA_PRIV + "\""
                + ",\"platformPublicKey\":\"" + RSA_PUB + "\""
                + ",\"serverRoot\":\"https://gw.example.com/gateway\"}";
    }

    /** base 追加字段（去尾大括号、补逗号、重新闭合）。 */
    private static String withField(String extra) {
        String b = base();
        return b.substring(0, b.length() - 1) + "," + extra + "}";
    }

    /** base 追加内容但不闭合（构造 EOF 场景）。 */
    private static String unterminated(String extra) {
        String b = base();
        return b.substring(0, b.length() - 1) + "," + extra;
    }

    private static WopError parseError(String json) {
        return assertThrows(WopError.class, () -> ConfigJsonParser.parse(json));
    }

    @Test
    void nullInputRejected() {
        assertTrue(parseError(null).getMessage().contains("空内容"));
    }

    @Test
    void blankInputRejected() {
        assertTrue(parseError("").getMessage().contains("空文件"));
        assertTrue(parseError("   ").getMessage().contains("空文件"));
    }

    @Test
    void bomStrippedBeforeParsing() {
        WopSdkConfig cfg = ConfigJsonParser.parse("﻿" + base());
        assertEquals("app_001", cfg.appKey());
    }

    @Test
    void rootMustBeObject() {
        assertTrue(parseError("[1]").getMessage().contains("期望 '{'"));
        assertTrue(parseError("1").getMessage().contains("期望 '{'"));
    }

    @Test
    void trailingContentRejected() {
        assertTrue(parseError(base() + " x").getMessage().contains("多余内容"));
    }

    @Test
    void unknownFieldsOfEveryJsonTypeSkipped() {
        WopSdkConfig cfg = ConfigJsonParser.parse(withField(
                "\"u1\":\"s\""
                        + ",\"u2\":{\"k\":1,\"deep\":{\"z\":[1,\"y\",true,null]}}"
                        + ",\"u3\":[1,2,[3],{\"w\":false}]"
                        + ",\"u4\":true,\"u5\":false,\"u6\":null,\"u7\":123"
                        + ",\"u8\":{},\"u9\":[]"));
        assertEquals("app_001", cfg.appKey());
    }

    @Test
    void nanAndInfinityRejected() {
        // 字面量防御仅作用于 t/f/n 开头的裸词：小写 nan 与含 infinity 的裸词拒绝
        assertTrue(parseError(withField("\"x\":nan")).getMessage().contains("NaN/Infinity"));
        assertTrue(parseError(withField("\"x\":fininfinity")).getMessage().contains("NaN/Infinity"));
    }

    @Test
    void eofInsideSkippedArray() {
        assertTrue(parseError(unterminated("\"x\":[")).getMessage().contains("意外结束"));
    }

    @Test
    void eofInsideSkippedObjectKey() {
        assertTrue(parseError(unterminated("\"x\":{")).getMessage().contains("期望字符串"));
    }

    @Test
    void escapeSequencesFullSpectrum() {
        String json = "{\"appKey\":\"a\\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti\""
                + ",\"suite\":\"WOP-RSA3072-SHA256\""
                + ",\"merchantPrivateKey\":\"" + RSA_PRIV + "\""
                + ",\"platformPublicKey\":\"" + RSA_PUB + "\""
                + ",\"serverRoot\":\"https://gw.example.com/gateway\"}";
        WopSdkConfig cfg = ConfigJsonParser.parse(json);
        assertEquals("a\"b\\c/d\be\ff\ng\rh\ti", cfg.appKey());
    }

    @Test
    void unicodeEscapesCoverHexBranches() {
        String json = "{\"appKey\":\"\\u0041\\u00E9\\u00e9z\""
                + ",\"suite\":\"WOP-RSA3072-SHA256\""
                + ",\"merchantPrivateKey\":\"" + RSA_PRIV + "\""
                + ",\"platformPublicKey\":\"" + RSA_PUB + "\""
                + ",\"serverRoot\":\"https://gw.example.com/gateway\"}";
        WopSdkConfig cfg = ConfigJsonParser.parse(json);
        assertEquals("Aééz", cfg.appKey());
    }

    @Test
    void unicodeEscapeIncompleteAtEof() {
        assertTrue(parseError(unterminated("\"x\":\"a\\u00")).getMessage().contains("\\u 转义不完整"));
    }

    @Test
    void unicodeEscapeIllegalHexDigit() {
        assertTrue(parseError(withField("\"x\":\"\\u00G0\"")).getMessage().contains("\\u 转义非法"));
    }

    @Test
    void illegalEscapeRejected() {
        assertTrue(parseError(withField("\"x\":\"a\\qb\"")).getMessage().contains("非法转义 \\q"));
    }

    @Test
    void escapeAtEofRejected() {
        assertTrue(parseError(unterminated("\"x\":\"a\\")).getMessage().contains("字符串转义不完整"));
    }

    @Test
    void unclosedStringRejected() {
        assertTrue(parseError(unterminated("\"x\":\"abc")).getMessage().contains("字符串未闭合"));
    }

    @Test
    void stringValueExpectedForNumber() {
        String json = "{\"appKey\":123"
                + ",\"suite\":\"WOP-RSA3072-SHA256\""
                + ",\"merchantPrivateKey\":\"" + RSA_PRIV + "\""
                + ",\"platformPublicKey\":\"" + RSA_PUB + "\""
                + ",\"serverRoot\":\"https://gw.example.com/gateway\"}";
        assertTrue(parseError(json).getMessage().contains("期望字符串"));
    }

    @Test
    void objectKeyMustBeString() {
        assertTrue(parseError("{123:1}").getMessage().contains("期望字符串"));
    }

    @Test
    void httpClientUnknownKeySkipped() {
        WopSdkConfig cfg = ConfigJsonParser.parse(withField(
                "\"httpClient\":{\"connectTimeout\":5000,\"future\":true}"));
        assertEquals(5000, cfg.httpClient().connectTimeout());
    }

    @Test
    void httpClientDuplicateKeyRejected() {
        assertTrue(parseError(withField(
                "\"httpClient\":{\"connectTimeout\":1,\"connectTimeout\":2}"))
                .getMessage().contains("重复"));
    }

    @Test
    void topLevelDuplicateKeyRejected() {
        assertTrue(parseError(withField("\"appKey\":\"dup\"")).getMessage().contains("重复"));
    }

    @Test
    void expiredSecondsMustBePositiveNumber() {
        assertTrue(parseError(withField("\"expiredSeconds\":-5"))
                .getMessage().contains("配置字段 expiredSeconds 类型非法: -5"));
        assertTrue(parseError(withField("\"expiredSeconds\":0"))
                .getMessage().contains("配置字段 expiredSeconds 类型非法: 0"));
    }

    @Test
    void longOutOfRangeRejected() {
        assertTrue(parseError(withField("\"expiredSeconds\":99999999999999999999"))
                .getMessage().contains("类型非法"));
    }

    @Test
    void numberExpectedForGarbage() {
        assertTrue(parseError(withField("\"expiredSeconds\":abc")).getMessage().contains("期望数字"));
        assertTrue(parseError(withField("\"expiredSeconds\":-")).getMessage().contains("期望数字"));
    }

    @Test
    void whitespaceAroundNumberTolerated() {
        WopSdkConfig cfg = ConfigJsonParser.parse(withField("\"expiredSeconds\": 60"));
        assertEquals(60L, cfg.expiredSeconds());
    }

    @Test
    void maxRetryCountValidation() {
        assertTrue(parseError(withField("\"httpClient\":{\"maxRetryCount\":-1}"))
                .getMessage().contains("配置字段 maxRetryCount 类型非法: -1"));
        assertTrue(parseError(withField("\"httpClient\":{\"maxRetryCount\":2147483648}"))
                .getMessage().contains("配置字段 httpClient 类型非法: 数值越界"));
    }

    @Test
    void connectTimeoutValidation() {
        assertTrue(parseError(withField("\"httpClient\":{\"connectTimeout\":0}"))
                .getMessage().contains("配置字段 connectTimeout 类型非法: 0"));
        assertTrue(parseError(withField("\"httpClient\":{\"connectTimeout\":2147483648}"))
                .getMessage().contains("数值越界"));
        assertTrue(parseError(withField("\"httpClient\":{\"connectTimeout\":1e3}"))
                .getMessage().contains("期望 ','"));
    }

    @Test
    void backupServerRootsMustBeArray() {
        assertTrue(parseError(withField("\"backupServerRoots\":{}")).getMessage().contains("期望 '['"));
    }

    @Test
    void backupServerRootsElementMustBeString() {
        assertTrue(parseError(withField("\"backupServerRoots\":[123]")).getMessage().contains("期望字符串"));
    }

    @Test
    void backupServerRootsUnterminated() {
        assertTrue(parseError(unterminated("\"backupServerRoots\":[\"https://b.example.com/gateway\""))
                .getMessage().contains("期望 ','"));
    }

    @Test
    void colonExpected() {
        assertTrue(parseError("{\"appKey\" \"a\"}").getMessage().contains("期望 ':'"));
    }

    @Test
    void commaExpected() {
        assertTrue(parseError("{\"appKey\":\"a\" \"suite\":\"x\"}").getMessage().contains("期望 ','"));
    }

    @Test
    void emptyObjectSurfacesFirstMissingField() {
        // 五个必填字符串全 null → 构造器空串缺省分支 → 校验器按序报 appKey
        assertTrue(parseError("{}").getMessage().contains("缺少必填项: appKey"));
    }

    @Test
    void httpClientPartialObjectFillsDefaults() {
        WopSdkConfig cfg = ConfigJsonParser.parse(withField("\"httpClient\":{\"readTimeout\":5000}"));
        assertEquals(HttpClientSettings.defaults().connectTimeout(), cfg.httpClient().connectTimeout());
        assertEquals(5000, cfg.httpClient().readTimeout());
        assertEquals(HttpClientSettings.defaults().maxRetryCount(), cfg.httpClient().maxRetryCount());
    }

    @Test
    void unicodeEscapeHexBoundaryDigitsRejected() {
        // 'g'：≥'a' 但 >'f'（小写下界命中、上界越出）；'-'：低于 '0'（数字下界外）
        assertTrue(parseError(withField("\"x\":\"\\u00g0\"")).getMessage().contains("\\u 转义非法"));
        assertTrue(parseError(withField("\"x\":\"\\u00-0\"")).getMessage().contains("\\u 转义非法"));
    }

    @Test
    void numberParsingAtEof() {
        // 数字起点即 EOF：'-' 检查与数字循环均以 len-F 退出 → 期望数字
        assertTrue(parseError(unterminated("\"httpClient\":{\"connectTimeout\":"))
                .getMessage().contains("期望数字"));
        // 数字后 EOF：数字循环 len-F 退出，随后逗号检查在 EOF 报错
        assertTrue(parseError(unterminated("\"httpClient\":{\"connectTimeout\":12"))
                .getMessage().contains("期望 ','"));
    }

    @Test
    void rawScanUnknownValueStopsAtStructuralDelimiters() {
        // 裸词扫描停在 '}'（对象收尾）与 ']'（数组元素收尾），整体仍合法
        assertEquals("app_001", ConfigJsonParser.parse(withField("\"u10\":abc")).appKey());
        assertEquals("app_001", ConfigJsonParser.parse(withField("\"u3b\":[abc]")).appKey());
        // EOF 退出裸词扫描后同样由逗号检查报错
        assertTrue(parseError(unterminated("\"u9\":xyz")).getMessage().contains("期望 ','"));
    }

    @Test
    void eofInsideSkippedLiteralTail() {
        // 字面量扫描到 EOF：循环 len-F 退出，"tru" 非 NaN/Infinity → 逗号检查报错
        assertTrue(parseError(unterminated("\"u4\":tru")).getMessage().contains("期望 ','"));
    }
}
