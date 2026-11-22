package com.wanlianyida.wop.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.wanlianyida.wop.TestText;
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
        byte[] key = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        assertEquals(32, key.length);
        assertEquals(TestVectors.input("aesKeyB64u"), Codec.b64UrlEncode(key));
    }

    @Test
    void b64UrlDecodeStrictRejectsPaddingVector() {
        String value = TestVectors.formatRuleValue("b64url-with-padding");
        assertEquals("abc=", value);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> Codec.b64UrlDecode(value));
        assertTrue(ex.getMessage().contains("base64url"));
    }

    @Test
    void b64UrlDecodeStrictRejectsIllegalCharVector() {
        assertEquals("ab+c", TestVectors.formatRuleValue("b64url-illegal-char"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("ab+c"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("ab/c"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("ab c"));
    }

    @Test
    void b64UrlDecodeStrictRejectsImpossibleLength() {
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("a"));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("abcde"));
    }

    // spec:formatRules-b64url —— 三件套：全量循环 + 未知 id/expect 哨兵 + 条数哨兵（6 条）
    @Test
    void b64UrlFormatRulesAllVectors() {
        int consumed = 0;
        for (JsonNode rule : TestVectors.root().withArray("formatRules")) {
            String id = rule.path("id").asText();
            if (!id.startsWith("b64url-")) {
                continue;   // header-* 族在 ContentDigestTest.formatRulesAllVectors 全量消费
            }
            consumed++;
            String value = rule.path("value").asText();
            String expect = rule.path("expect").asText();
            switch (id) {
                case "b64url-with-padding":
                case "b64url-illegal-char":
                case "b64url-trailing-bits-noncanonical-2":
                case "b64url-trailing-bits-noncanonical-3": {
                    assertEquals("reject", expect, id + " expect 哨兵");
                    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                            () -> Codec.b64UrlDecode(value), id + " 须拒收");
                    assertTrue(ex.getMessage().contains("base64url"));
                    break;
                }
                case "b64url-trailing-bits-canonical-2": {
                    assertEquals("accept", expect, id + " expect 哨兵");
                    assertArrayEquals(new byte[]{0x00}, Codec.b64UrlDecode(value));
                    break;
                }
                case "b64url-trailing-bits-canonical-3": {
                    assertEquals("accept", expect, id + " expect 哨兵");
                    assertArrayEquals(new byte[]{0x4D, 0x61}, Codec.b64UrlDecode(value));
                    break;
                }
                default:
                    throw new IllegalStateException("未预期 b64url 向量 id: " + id);
            }
        }
        assertEquals(6, consumed, "b64url-* 条数哨兵（真源 formatRules 12 条中 b64url 族 6 条）");
    }

    @Test
    void b64UrlDecodeRejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode(null));
    }

    @Test
    void hexLowerProducesLowercaseHex() {
        byte[] data = {(byte) 0xAB, (byte) 0xCD, 0x01, (byte) 0xEF};
        assertEquals("abcd01ef", Codec.hexLower(data));
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
        assertTrue(Codec.isLowerHex64(TestText.repeat("0", 64)));
        assertFalse(Codec.isLowerHex64(TestText.repeat("0", 63)));
        assertFalse(Codec.isLowerHex64(TestText.repeat("0", 65)));
        assertFalse(Codec.isLowerHex64(TestText.repeat("ABCDEF", 10) + "ab"));
        assertFalse(Codec.isLowerHex64(TestText.repeat("g", 64)));
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

    @Test
    void b64UrlUrlSafeAlphabetTrailingBitsRejected() {
        IllegalArgumentException dash = assertThrows(IllegalArgumentException.class,
                () -> Codec.b64UrlDecode("AB-"));
        assertTrue(dash.getMessage().contains("尾随位非零"));
        IllegalArgumentException underscore = assertThrows(IllegalArgumentException.class,
                () -> Codec.b64UrlDecode("AB_"));
        assertTrue(underscore.getMessage().contains("尾随位非零"));
    }
}
