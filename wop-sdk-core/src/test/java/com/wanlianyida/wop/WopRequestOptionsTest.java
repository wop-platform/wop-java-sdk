package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * WopRequestOptions 值语义：none 单例、has* 判定矩阵、isEmpty、
 * equals 十字段、toString 与 Builder 参数守卫（§6.1）。
 */
class WopRequestOptionsTest {

    @Test
    void noneIsSingletonAndEmpty() {
        assertSame(WopRequestOptions.none(), WopRequestOptions.none());
        WopRequestOptions none = WopRequestOptions.none();
        assertTrue(none.isEmpty());
        assertNull(none.appKey());
        assertNull(none.suite());
        assertNull(none.merchantPrivateKey());
        assertNull(none.platformPublicKey());
        assertEquals(0L, none.expiredSeconds());
        assertNull(none.serverRoot());
        assertEquals(0, none.connectTimeout());
        assertEquals(0, none.readTimeout());
        assertNull(none.requestId());
        assertNull(none.subMchId());
    }

    @Test
    void stringHasPredicates() {
        for (String blank : new String[]{null, "", "   "}) {
            assertFalse(WopRequestOptions.builder().appKey(blank).build().hasAppKey());
            assertFalse(WopRequestOptions.builder().suite(blank).build().hasSuite());
            assertFalse(WopRequestOptions.builder().merchantPrivateKey(blank).build().hasMerchantPrivateKey());
            assertFalse(WopRequestOptions.builder().platformPublicKey(blank).build().hasPlatformPublicKey());
            assertFalse(WopRequestOptions.builder().serverRoot(blank).build().hasServerRoot());
            assertFalse(WopRequestOptions.builder().requestId(blank).build().hasRequestId());
            assertFalse(WopRequestOptions.builder().subMchId(blank).build().hasSubMchId());
        }
        assertTrue(WopRequestOptions.builder().appKey("a").build().hasAppKey());
        assertTrue(WopRequestOptions.builder().suite("s").build().hasSuite());
        assertTrue(WopRequestOptions.builder().merchantPrivateKey("m").build().hasMerchantPrivateKey());
        assertTrue(WopRequestOptions.builder().platformPublicKey("p").build().hasPlatformPublicKey());
        assertTrue(WopRequestOptions.builder().serverRoot("https://x.example.com/gateway").build().hasServerRoot());
        assertTrue(WopRequestOptions.builder().requestId("req-001").build().hasRequestId());
        assertTrue(WopRequestOptions.builder().subMchId("PLF-SUB-001").build().hasSubMchId());
    }

    @Test
    void numericHasPredicates() {
        assertFalse(WopRequestOptions.builder().expiredSeconds(0L).build().hasExpiredSeconds());
        assertTrue(WopRequestOptions.builder().expiredSeconds(60L).build().hasExpiredSeconds());
        assertFalse(WopRequestOptions.builder().connectTimeout(0).build().hasConnectTimeout());
        assertTrue(WopRequestOptions.builder().connectTimeout(2500).build().hasConnectTimeout());
        assertFalse(WopRequestOptions.builder().readTimeout(0).build().hasReadTimeout());
        assertTrue(WopRequestOptions.builder().readTimeout(3500).build().hasReadTimeout());
    }

    @Test
    void isEmptyFalseWhenAnyFieldSet() {
        assertFalse(WopRequestOptions.builder().appKey("a").build().isEmpty());
        assertFalse(WopRequestOptions.builder().suite("s").build().isEmpty());
        assertFalse(WopRequestOptions.builder().merchantPrivateKey("m").build().isEmpty());
        assertFalse(WopRequestOptions.builder().platformPublicKey("p").build().isEmpty());
        assertFalse(WopRequestOptions.builder().expiredSeconds(60L).build().isEmpty());
        assertFalse(WopRequestOptions.builder().serverRoot("https://x.example.com/gateway").build().isEmpty());
        assertFalse(WopRequestOptions.builder().connectTimeout(1).build().isEmpty());
        assertFalse(WopRequestOptions.builder().readTimeout(1).build().isEmpty());
        assertFalse(WopRequestOptions.builder().requestId("req").build().isEmpty());
        assertFalse(WopRequestOptions.builder().subMchId("PLF-SUB-001").build().isEmpty());
    }

    @Test
    void equalsAndHashCodeVaryEachField() {
        WopRequestOptions base = full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001");
        assertEquals(base, base);
        assertEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertEquals(base.hashCode(), full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001").hashCode());
        assertNotEquals(base, null);
        assertNotEquals(base, "x");
        assertNotEquals(base, full("z", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "z", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "z", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "z", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "p", 61L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://z.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 1, 3500, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 1, "req-001", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-002", "PLF-SUB-001"));
        assertNotEquals(base, full("a", "s", "m", "p", 60L, "https://x.example.com/gateway", 2500, 3500, "req-001", "PLF-SUB-002"));
    }

    @Test
    void emptyBuildEqualsNone() {
        assertEquals(WopRequestOptions.none(), WopRequestOptions.builder().build());
        assertEquals(WopRequestOptions.builder().build(), WopRequestOptions.none());
    }

    @Test
    void toStringMasksCredentials() {
        String s = WopRequestOptions.builder()
                .appKey("a").suite("s").merchantPrivateKey("secret-m").platformPublicKey("secret-p")
                .requestId("req-042").subMchId("PLF-SUB-001")
                .build().toString();
        assertTrue(s.contains("merchantPrivateKey=****"));
        assertTrue(s.contains("platformPublicKey=****"));
        assertFalse(s.contains("secret-m"));
        assertFalse(s.contains("secret-p"));
        assertTrue(s.contains("requestId=req-042"));
        assertTrue(s.contains("subMchId=PLF-SUB-001"));
    }

    @Test
    void builderRejectsNegatives() {
        WopError e1 = assertThrows(WopError.class, () -> WopRequestOptions.builder().expiredSeconds(-1L));
        assertTrue(e1.getMessage().contains("expiredSeconds 不能为负数"));
        WopError e2 = assertThrows(WopError.class, () -> WopRequestOptions.builder().connectTimeout(-1));
        assertTrue(e2.getMessage().contains("connectTimeout 不能为负数"));
        WopError e3 = assertThrows(WopError.class, () -> WopRequestOptions.builder().readTimeout(-1));
        assertTrue(e3.getMessage().contains("readTimeout 不能为负数"));
    }

    @Test
    void builderRejectsRequestIdWithControlCharacters() {
        // CR (0x0D) and LF (0x0A) are both < 0x20, rejected as control characters
        String withCrLf = "bad" + String.valueOf('\r') + String.valueOf('\n') + "x-inject: 1";

        // CR+LF test
        try {
            WopRequestOptions.builder().requestId(withCrLf).build();
            fail("Expected WopError for CR+LF");
        } catch (WopError e) {
            assertTrue(e.getMessage().contains("控制字符"), "Expected 控制字符 in: " + e.getMessage());
        }

        // NUL test
        try {
            WopRequestOptions.builder().requestId("bad\u0000id").build();
            fail("Expected WopError for NUL");
        } catch (WopError e) {
            assertTrue(e.getMessage().contains("控制字符"));
        }

        // DEL test
        try {
            WopRequestOptions.builder().requestId("bad\u007fid").build();
            fail("Expected WopError for DEL");
        } catch (WopError e) {
            assertTrue(e.getMessage().contains("控制字符"));
        }
    }

    @Test
    void resolvedRequestIdTrimsAndNormalizes() {
        // null / pure whitespace → null (hasRequestId=false)
        assertNull(WopRequestOptions.builder().requestId(null).build().requestId());
        assertFalse(WopRequestOptions.builder().requestId("  ").build().hasRequestId());
        assertNull(WopRequestOptions.builder().requestId("  ").build().resolvedRequestId());
        // raw field preserves whitespace; resolvedRequestId trims
        assertEquals("  req-001  ", WopRequestOptions.builder().requestId("  req-001  ").build().requestId());
        assertEquals("req-001", WopRequestOptions.builder().requestId("  req-001  ").build().resolvedRequestId());
    }

    @Test
    void requestIdLengthLimit() {
        // 128 ASCII 字节 OK
        String len128 = repeat('a', 128);
        assertEquals(len128, WopRequestOptions.builder().requestId(len128).build().resolvedRequestId());
        // 129 字节 rejected
        try {
            WopRequestOptions.builder().requestId(repeat('a', 129)).build();
            fail("Expected WopError for 129-byte requestId");
        } catch (WopError e) {
            assertTrue(e.getMessage().contains("128"), "Expected 128 in: " + e.getMessage());
        }
    }

    @Test
    void requestIdLengthMeasuredInUtf8BytesNotChars() {
        // 附录 I/I2：长度单位为 trim 后 UTF-8 编码字节数（非 UTF-16 字符数）。
        // 中文字符 1 字符 = 1 UTF-16 单元 = 3 UTF-8 字节：100 字符仅 100 单元但 300 字节 → 必须拒
        String cjk100 = repeat('中', 100);
        assertEquals(100, cjk100.length());
        try {
            WopRequestOptions.builder().requestId(cjk100).build();
            fail("Expected WopError: 100 CJK chars = 300 UTF-8 bytes > 128");
        } catch (WopError e) {
            assertTrue(e.getMessage().contains("UTF-8"), "Expected UTF-8 in: " + e.getMessage());
        }
        // 42 中文字符 = 126 字节 ≤ 128 → 通过
        String cjk42 = repeat('中', 42);
        assertEquals(cjk42, WopRequestOptions.builder().requestId(cjk42).build().resolvedRequestId());
    }

    private static String repeat(char c, int count) {
        char[] arr = new char[count];
        java.util.Arrays.fill(arr, c);
        return new String(arr);
    }

    @Test
    void requestIdControlCharsCheckedOnRawBeforeTrim() {
        // 首尾 CR/LF 先被查到（在 trim 之前）
        WopError e1 = assertThrows(WopError.class,
                () -> WopRequestOptions.builder().requestId("req-1\r\n").build());
        assertTrue(e1.getMessage().contains("控制字符"));
        // 内部的控制字符也直接被拒绝（trim 前后都能查到）
        WopError e2 = assertThrows(WopError.class,
                () -> WopRequestOptions.builder().requestId("req\u00001").build());
        assertTrue(e2.getMessage().contains("控制字符"));
    }

    @Test
    void resolvedSubMchIdTrimsAndNormalizes() {
        // null / 纯空白 → 头缺席（应用自身身份）
        assertNull(WopRequestOptions.builder().subMchId(null).build().subMchId());
        assertFalse(WopRequestOptions.builder().subMchId("  ").build().hasSubMchId());
        assertNull(WopRequestOptions.builder().subMchId("  ").build().resolvedSubMchId());
        // 原始值保留空白，resolved 去首尾空白（与网关 trim 后查询值一致）
        assertEquals("  PLF-SUB-001  ", WopRequestOptions.builder().subMchId("  PLF-SUB-001  ").build().subMchId());
        assertEquals("PLF-SUB-001", WopRequestOptions.builder().subMchId("  PLF-SUB-001  ").build().resolvedSubMchId());
    }

    @Test
    void builderRejectsSubMchIdViolations() {
        // 控制字符（CR/LF/NUL/DEL）与制表符：头注入/签名歧义
        String withCrLf = "bad" + String.valueOf('\r') + String.valueOf('\n') + "x: 1";
        for (String bad : new String[]{withCrLf, "bad\u0000id", "bad\u007fid", "bad\tid"}) {
            WopError e = assertThrows(WopError.class,
                    () -> WopRequestOptions.builder().subMchId(bad).build());
            assertTrue(e.getMessage().contains("可打印 ASCII"), "Expected ASCII guard in: " + e.getMessage());
            assertEquals(WopError.Category.configuration, e.category());
        }
        // 非 ASCII（中文）
        WopError cjk = assertThrows(WopError.class,
                () -> WopRequestOptions.builder().subMchId("PLF中文").build());
        assertTrue(cjk.getMessage().contains("可打印 ASCII"));
        assertEquals(WopError.Category.configuration, cjk.category());
        // 内部空白：网关 trimall 折叠后签名与身份查询不再一一对应
        WopError space = assertThrows(WopError.class,
                () -> WopRequestOptions.builder().subMchId("PLF SUB").build());
        assertTrue(space.getMessage().contains("内部空白"));
        assertEquals(WopError.Category.configuration, space.category());
    }

    @Test
    void subMchIdLengthLimit() {
        String len128 = repeat('a', 128);
        assertEquals(len128, WopRequestOptions.builder().subMchId(len128).build().resolvedSubMchId());
        WopError e = assertThrows(WopError.class,
                () -> WopRequestOptions.builder().subMchId(repeat('a', 129)).build());
        assertTrue(e.getMessage().contains("128"), "Expected 128 in: " + e.getMessage());
        assertEquals(WopError.Category.configuration, e.category());
    }

    @Test
    void subMchIdPrintableAsciiBoundariesAccepted() {
        // 0x20 与 0x7E 是合法边界：空格可 trim，~ 是上界可打印字符（A9/J2）
        assertEquals("!~", WopRequestOptions.builder().subMchId(" !~ ").build().resolvedSubMchId());
        assertEquals(128, WopRequestOptions.builder().subMchId(repeat('~', 128))
                .build().resolvedSubMchId().length());
    }

    @Test
    void hasConfigOverridesOnlyReturnsTrueForConfigFields() {
        // 仅 requestId → hasConfigOverrides = false
        WopRequestOptions onlyReqId = WopRequestOptions.builder().requestId("req-001").build();
        assertTrue(onlyReqId.hasRequestId());
        assertFalse(onlyReqId.hasConfigOverrides());
        assertFalse(onlyReqId.isEmpty()); // isEmpty 仍考虑 requestId
        assertFalse(onlyReqId.hasInboundOverrides()); // 入向凭证不看 requestId

        // 仅 subMchId → 出向身份字段：非空但不需要 sdkConfig，也不是入向凭证覆盖
        WopRequestOptions onlySubMch = WopRequestOptions.builder().subMchId("PLF-SUB-001").build();
        assertTrue(onlySubMch.hasSubMchId());
        assertFalse(onlySubMch.hasConfigOverrides());
        assertFalse(onlySubMch.isEmpty());
        assertFalse(onlySubMch.hasInboundOverrides());

        // 逐字段覆盖短路 OR 链的每个分支位（前序全 false + 当前字段 true）
        assertTrue(single(b -> b.appKey("app")).hasConfigOverrides());
        assertTrue(single(b -> b.suite("WOP-RSA3072-SHA256")).hasConfigOverrides());
        assertTrue(single(b -> b.merchantPrivateKey("k")).hasConfigOverrides());
        assertTrue(single(b -> b.platformPublicKey("p")).hasConfigOverrides());
        assertTrue(single(b -> b.expiredSeconds(60L)).hasConfigOverrides());
        assertTrue(single(b -> b.serverRoot("https://gw.example.com")).hasConfigOverrides());
        assertTrue(single(b -> b.connectTimeout(1)).hasConfigOverrides());
        assertTrue(single(b -> b.readTimeout(1)).hasConfigOverrides());

        // none → false
        assertFalse(WopRequestOptions.none().hasConfigOverrides());
    }

    @Test
    void hasInboundOverridesOnlyReturnsTrueForCredentialFields() {
        // 逐字段覆盖短路 OR 链的每个分支位（前序全 false + 当前字段 true）
        assertTrue(single(b -> b.appKey("app")).hasInboundOverrides());
        assertTrue(single(b -> b.suite("WOP-RSA3072-SHA256")).hasInboundOverrides());
        assertTrue(single(b -> b.merchantPrivateKey("k")).hasInboundOverrides());
        assertTrue(single(b -> b.platformPublicKey("p")).hasInboundOverrides());
        // 非凭证字段 → false（含全 false 分支）
        assertFalse(single(b -> b.expiredSeconds(60L)).hasInboundOverrides());
        assertFalse(single(b -> b.serverRoot("https://gw.example.com")).hasInboundOverrides());
        assertFalse(single(b -> b.connectTimeout(1)).hasInboundOverrides());
        assertFalse(single(b -> b.readTimeout(1)).hasInboundOverrides());
        assertFalse(WopRequestOptions.none().hasInboundOverrides());
    }

    private static WopRequestOptions single(java.util.function.UnaryOperator<WopRequestOptions.Builder> fn) {
        return fn.apply(WopRequestOptions.builder()).build();
    }

    private static WopRequestOptions full(String appKey, String suite, String merchant, String platform,
                                          long expired, String serverRoot, int connectTimeout, int readTimeout,
                                          String requestId, String subMchId) {
        return WopRequestOptions.builder()
                .appKey(appKey).suite(suite).merchantPrivateKey(merchant).platformPublicKey(platform)
                .expiredSeconds(expired).serverRoot(serverRoot)
                .connectTimeout(connectTimeout).readTimeout(readTimeout)
                .requestId(requestId).subMchId(subMchId).build();
    }
}
