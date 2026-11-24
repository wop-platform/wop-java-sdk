package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PIT r2 补测：协议头的拒绝路径（NegateConditionals / ConditionalsBoundary / MathMutator 变异）。
 * 断言具体消息而非仅异常类型，守卫被删或条件被取反即红。
 */
class MutationKillHeaderTest {

    private static final AlgorithmSuite SUITE = AlgorithmSuite.parse("WOP-RSA3072-SHA256");

    private static String messageOf(Throwable error) {
        return error.getMessage() == null ? "" : error.getMessage();
    }

    // ==================== AlgorithmSuite.parse ====================

    @Test
    void parseUnknownKeyAlgorithmReportsActualSegment() {
        WopSuiteException error = assertThrows(WopSuiteException.class,
                () -> AlgorithmSuite.parse("WOP-FOO-SHA256"));
        assertTrue(messageOf(error).contains("不支持的算法: 'FOO'"), messageOf(error));
    }

    @Test
    void parseUnknownDigestAlgorithmReportsActualSegment() {
        WopSuiteException error = assertThrows(WopSuiteException.class,
                () -> AlgorithmSuite.parse("WOP-RSA3072-FOO"));
        assertTrue(messageOf(error).contains("不支持的算法: 'FOO'"), messageOf(error));
    }

    @Test
    void parseCrossFamilyCombinationRejected() {
        WopSuiteException error = assertThrows(WopSuiteException.class,
                () -> AlgorithmSuite.parse("WOP-RSA3072-SM3"));
        assertTrue(messageOf(error).contains("不支持的算法组合: 'WOP-RSA3072-SM3'"), messageOf(error));
    }

    // ==================== Codec.b64UrlDecode ====================

    @Test
    void b64UrlDecodeRejectsLengthMod4One() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> Codec.b64UrlDecode("AAAAA"));
        assertTrue(messageOf(error).contains("mod 4 == 1"), messageOf(error));
    }

    // ==================== ContentDigest.parse ====================

    @Test
    void contentDigestRejectsLeadingSpaceLabel() {
        String hex = Codec.hexLower(new byte[32]);
        WopError error = assertThrows(WopError.class, () -> ContentDigest.parse(" " + hex, SUITE));
        // space==0 时服务于标签校验，而非「缺少分隔」；边界变异会提前走错分支
        assertTrue(messageOf(error).contains("标签 ''"), messageOf(error));
    }

    // ==================== EncryptHeader.parse ====================

    @Test
    void encryptHeaderLeadingSemicolonReportsEmptyLevel() {
        WopError error = assertThrows(WopError.class, () -> EncryptHeader.parse(";dek=abc"));
        assertTrue(messageOf(error).contains("实际 ''"), messageOf(error));
    }
}
