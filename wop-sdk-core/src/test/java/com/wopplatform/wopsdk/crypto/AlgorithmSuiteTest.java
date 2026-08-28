package com.wopplatform.wopsdk.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * F1 套件配置与解析：三套件全支持，跨族/非法拒绝（crypto spec §2）。
 */
class AlgorithmSuiteTest {

    @Test
    void parsesRsa3072Suite() {
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
        assertEquals("WOP-RSA3072-SHA256", suite.securityReq());
        assertEquals("RSA", suite.keyAlgorithm());
        assertEquals(3072, suite.keyLength());
        assertEquals("SHA256", suite.digestAlgorithm());
        assertEquals("sha-256", suite.digestLabel());
        assertEquals("AES-256-GCM", suite.expectedDekAlg());
        assertEquals("SHA256withRSA", suite.signature().algorithmName());
    }

    @Test
    void parsesRsa4096Suite() {
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-RSA4096-SHA256");
        assertEquals(4096, suite.keyLength());
        assertEquals("RSA", suite.keyAlgorithm());
        assertEquals("sha-256", suite.digestLabel());
        assertEquals("AES-256-GCM", suite.expectedDekAlg());
    }

    @Test
    void parsesSm2Suite() {
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-SM2-SM3");
        assertEquals("SM2", suite.keyAlgorithm());
        assertEquals(0, suite.keyLength());
        assertEquals("SM3", suite.digestAlgorithm());
        assertEquals("sm3", suite.digestLabel());
        assertEquals("SM4-GCM", suite.expectedDekAlg());
        assertEquals("SM3withSM2", suite.signature().algorithmName());
        assertEquals("SM2", suite.keyEncrypt().algorithmName());
        assertEquals("SM4-GCM", suite.messageEncrypt().algorithmName());
        assertEquals("SM3", suite.digest().algorithmName());
    }

    @Test
    void rsaSuitesExposeCorrectStrategyNames() {
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
        assertEquals("RSA-OAEP(SHA-256/MGF1-SHA-256)", suite.keyEncrypt().algorithmName());
        assertEquals("AES-256-GCM", suite.messageEncrypt().algorithmName());
        assertEquals("SHA-256", suite.digest().algorithmName());
    }

    @Test
    void messageEncryptParamsMatchSpec() {
        assertEquals(32, AlgorithmSuite.parse("WOP-RSA3072-SHA256").messageEncrypt().keyLength());
        assertEquals(12, AlgorithmSuite.parse("WOP-RSA3072-SHA256").messageEncrypt().ivLength());
        assertEquals(16, AlgorithmSuite.parse("WOP-SM2-SM3").messageEncrypt().keyLength());
        assertEquals(12, AlgorithmSuite.parse("WOP-SM2-SM3").messageEncrypt().ivLength());
    }

    // ==================== 解析类拒绝（明确指出格式错误） ====================

    @Test
    void rejectsBlank() {
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse(null));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse(""));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("   "));
    }

    @Test
    void rejectsBadFormat() {
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("RSA3072-SHA256"));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("XOP-RSA3072-SHA256"));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("WOP-RSA3072"));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("WOP-RSA3072-SHA256-EXTRA"));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("WOP--SHA256"));
    }

    // ==================== 支持类拒绝（不支持的算法组合） ====================

    @Test
    void rejectsUnsupportedAlgorithms() {
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("WOP-RSA2048-SHA256"));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("WOP-RSA3072-SHA384"));
        assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("WOP-ED25519-SHA256"));
    }

    @Test
    void rejectsCrossFamilyCombination() {
        // I5：国际密钥 + 国密摘要 / 国密密钥 + 国际摘要，禁止
        WopSuiteException e1 = assertThrows(WopSuiteException.class,
                () -> AlgorithmSuite.parse("WOP-RSA3072-SM3"));
        WopSuiteException e2 = assertThrows(WopSuiteException.class,
                () -> AlgorithmSuite.parse("WOP-SM2-SHA256"));
        assertEquals(WopSuiteException.Kind.UNSUPPORTED, e1.kind());
        assertEquals(WopSuiteException.Kind.UNSUPPORTED, e2.kind());
    }

    @Test
    void distinguishesParseKindFromUnsupportedKind() {
        assertEquals(WopSuiteException.Kind.PARSE,
                assertThrows(WopSuiteException.class, () -> AlgorithmSuite.parse("junk")).kind());
    }
}
