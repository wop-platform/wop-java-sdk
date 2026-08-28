package com.wopplatform.wopsdk.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 线上编码 Codec：base64url 无填充严格模式（F7/D10）与小写 hex（D2）。
 * 负向量来自黄金向量 formatRules（b64url-with-padding / b64url-illegal-char）。
 */
class CodecTest {

    @Test
    void b64UrlRoundtripWithoutPadding() {
        byte[] data = {0x00, 0x01, 0x02, (byte) 0xFF, (byte) 0xFE, 0x7F, 0x41};
        String encoded = Codec.b64UrlEncode(data);
        assertFalse(encoded.contains("="));
        assertFalse(encoded.contains("+"));
        assertFalse(encoded.contains("/"));
        assertArrayEquals(data, Codec.b64UrlDecode(encoded));
    }

    @Test
    void b64UrlEncodeMatchesVectorInput() {
        // inputs.aesKeyB64u = 32B 密钥的 base64url 无填充形态
        byte[] key = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        assertEquals(32, key.length);
        assertEquals(TestVectors.input("aesKeyB64u"), Codec.b64UrlEncode(key));
    }

    @Test
    void b64UrlDecodeStrictRejectsPaddingVector() {
        // formatRules: b64url-with-padding → "abc=" 必须拒绝（F6 严格无填充）
        String value = TestVectors.formatRuleValue("b64url-with-padding");
        assertEquals("abc=", value);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> Codec.b64UrlDecode(value));
        assertTrue(ex.getMessage().contains("base64url"));
    }

    @Test
    void b64UrlDecodeStrictRejectsIllegalCharVector() {
        // formatRules: b64url-illegal-char → "ab+c" 必须拒绝（标准字母表 + / 同拒）
        assertEquals("ab+c", TestVectors.formatRuleValue("b64url-illegal-char"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("ab+c"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("ab/c"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("ab c"));
    }

    @Test
    void b64UrlDecodeStrictRejectsImpossibleLength() {
        // 长度 mod 4 == 1 不可能是合法 base64
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("a"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("abcde"));
    }

    @Test
    void b64UrlDecodeRejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode(null));
    }

    @Test
    void hexLowerProducesLowercaseHex() {
        byte[] data = {(byte) 0xAB, (byte) 0xCD, 0x01, (byte) 0xEF};
        assertEquals("abcd01ef", Codec.hexLower(data));
        // 空 → 空串
        assertEquals("", Codec.hexLower(new byte[0]));
    }

    @Test
    void hexLowerMatchesDigestVectorShape() {
        // digest-sha256.expectedHex 为 64 位小写 hex（此处仅校验形态函数，字节级断言在摘要策略测试）
        String hex = TestVectors.firstById("digest", "digest-sha256").path("expectedHex").asText();
        assertTrue(Codec.isLowerHex64(hex));
    }

    @Test
    void isLowerHex64RejectsViolations() {
        assertTrue(Codec.isLowerHex64("0".repeat(64)));
        assertFalse(Codec.isLowerHex64("0".repeat(63)));                 // 长度不足（header-wrong-hex-len 同源）
        assertFalse(Codec.isLowerHex64("0".repeat(65)));
        assertFalse(Codec.isLowerHex64("ABCDEF".repeat(10) + "ab"));     // 大写（header-uppercase-hex 同源）
        assertFalse(Codec.isLowerHex64("g".repeat(64)));                 // 非 hex 字符
        assertFalse(Codec.isLowerHex64(null));
        assertFalse(Codec.isLowerHex64(""));
    }

    @Test
    void utf8BytesStable() {
        assertArrayEquals("WOP".getBytes(StandardCharsets.UTF_8), Codec.utf8("WOP"));
    }

    @Test
    void concatJoinsBytes() {
        byte[] a = {1, 2};
        byte[] b = {3};
        assertArrayEquals(new byte[]{1, 2, 3}, Codec.concat(a, b));
        assertTrue(Arrays.equals(new byte[0], Codec.concat(new byte[0], new byte[0])));
    }
}
