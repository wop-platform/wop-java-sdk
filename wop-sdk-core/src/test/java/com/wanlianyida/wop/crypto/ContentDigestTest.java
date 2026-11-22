package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F4/D2 x-wop-content-digest 全语义：
 * 无 body（GET/空体）→ 缺席；有 body 必产 `alg 小写hex` 恰一空格；
 * formatRules 黄金向量全量（跨族/双空格/大写 hex/长度非法全拒）。
 */
class ContentDigestTest {

    private static final AlgorithmSuite RSA = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    @Test
    void buildsDigestHeaderFromWireBody() {
        JsonNode vector = TestVectors.firstById("digest", "digest-sha256");
        byte[] body = Codec.utf8(vector.path("input").asText());
        assertEquals(vector.path("expectedHeader").asText(), ContentDigest.build(RSA, body));
    }

    @Test
    void buildsSm3HeaderForSm2Suite() {
        JsonNode vector = TestVectors.firstById("digest", "digest-sm3");
        byte[] body = Codec.utf8(vector.path("input").asText());
        assertEquals(vector.path("expectedHeader").asText(), ContentDigest.build(SM2, body));
    }

    @Test
    void absentBodyProducesNoHeader() {
        // D2：无 body（GET/空体）→ header 缺席，不定义"空串摘要"中间态
        assertNull(ContentDigest.build(RSA, null));
        assertNull(ContentDigest.build(RSA, new byte[0]));
        assertNull(ContentDigest.build(SM2, null));
    }

    @Test
    void digestObjectIsWireBytesNotPlaintext() {
        // 摘要对象 = 线上原始报文字节（任意二进制）
        byte[] wire = {0x00, 0x01, 0x02, 0x7F, (byte) 0xFF};
        String header = ContentDigest.build(RSA, wire);
        String expectedHex = Codec.hexLower(RSA.digest().digest(wire));
        assertEquals("sha-256 " + expectedHex, header);
    }

    @Test
    void formatRulesAllVectors() {
        // spec:formatRules —— 三件套：全量循环（header-* 走 ContentDigest，b64url-* 走 Codec）
        // + 未知 id/expect 哨兵 + 条数哨兵（12）
        JsonNode rules = TestVectors.root().withArray("formatRules");
        assertEquals(12, rules.size(), "formatRules 条数哨兵（真源升格后 12 条）");
        for (JsonNode rule : rules) {
            String id = rule.path("id").asText();
            String value = rule.path("value").asText();
            String expect = rule.path("expect").asText();
            AlgorithmSuite suite = AlgorithmSuite.parse(rule.path("suite").asText("WOP-RSA3072-SHA256"));
            switch (id) {
                case "header-rsa-ok":
                case "header-sm2-ok": {
                    assertEquals("accept", expect, id + " expect 哨兵");
                    ContentDigest.parse(value, suite);
                    break;
                }
                case "header-crossfamily":
                case "header-double-space":
                case "header-uppercase-hex":
                case "header-wrong-hex-len": {
                    assertEquals("reject", expect, id + " expect 哨兵");
                    WopError ex = assertThrows(WopError.class,
                            () -> ContentDigest.parse(value, suite), id + " 须拒收");
                    // spec:2.2 解析错误闭集：digest 头违规归 parse
                    assertEquals(WopError.Category.parse, ex.category());
                    // 错误明确指出格式问题（解析类，非模糊）
                    assertTrue(ex.getMessage() != null && !ex.getMessage().trim().isEmpty());
                    break;
                }
                case "b64url-with-padding":
                case "b64url-illegal-char":
                case "b64url-trailing-bits-noncanonical-2":
                case "b64url-trailing-bits-noncanonical-3": {
                    assertEquals("reject", expect, id + " expect 哨兵");
                    assertThrows(IllegalArgumentException.class,
                            () -> Codec.b64UrlDecode(value), id + " 须拒收");
                    break;
                }
                case "b64url-trailing-bits-canonical-2": {
                    assertEquals("accept", expect, id + " expect 哨兵");
                    assertArrayEquals(new byte[]{0x00}, Codec.b64UrlDecode(value));        // "AA"
                    break;
                }
                case "b64url-trailing-bits-canonical-3": {
                    assertEquals("accept", expect, id + " expect 哨兵");
                    assertArrayEquals(new byte[]{0x4D, 0x61}, Codec.b64UrlDecode(value));  // "TWE" → "Ma"
                    break;
                }
                default:
                    throw new IllegalStateException("未预期 formatRules 向量 id: " + id);
            }
        }
    }

    @Test
    void parseExtractsHexForRecompute() {
        JsonNode vector = TestVectors.firstById("digest", "digest-sha256");
        ContentDigest.Parsed parsed = ContentDigest.parse(vector.path("expectedHeader").asText(), RSA);
        assertEquals(vector.path("expectedHex").asText(), parsed.hex());
        assertEquals("sha-256", parsed.label());
    }

    @Test
    void parseRejectsBlankAndMalformed() {
        assertThrows(WopError.class, () -> ContentDigest.parse(null, RSA));
        assertThrows(WopError.class, () -> ContentDigest.parse("", RSA));
        assertThrows(WopError.class, () -> ContentDigest.parse("sha-256", RSA));       // 无空格
        assertThrows(WopError.class, () -> ContentDigest.parse("sha-256 ", RSA));      // 空 hex
        assertThrows(WopError.class, () -> ContentDigest.parse(" sha-256 ab", RSA));   // 前导空格
        assertThrows(WopError.class, () -> ContentDigest.parse("sha-256\t4cf7", RSA)); // 制表符
    }

    @Test
    void crossFamilyLabelRejected() {
        // I5：sm3 标签配 RSA 套件 / sha-256 配 SM2 套件
        assertThrows(WopError.class, () -> ContentDigest.parse(
                "sm3 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", RSA));
        assertThrows(WopError.class, () -> ContentDigest.parse(
                "sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", SM2));
    }
}
