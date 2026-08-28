package com.wopplatform.wopsdk.crypto;

import com.wopplatform.wopsdk.WopSdkException;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DEK 载荷（alg$key$iv）与 x-wop-sign / x-wop-encrypt 头编解码。
 */
class ProtocolHeaderTest {

    // ==================== DekPayload ====================

    @Test
    void dekPayloadEncodeMatchesGoldenVectors() {
        for (String id : new String[]{"dek-rsa", "dek-sm2"}) {
            var vector = TestVectors.firstById("dekPayload", id);
            byte[] key = Codec.b64UrlDecode(vector.path("keyB64u").asText());
            byte[] iv = Codec.b64UrlDecode(vector.path("ivB64u").asText());
            assertEquals(vector.path("expected").asText(),
                    DekPayload.encode(new DekPayload(vector.path("alg").asText(), key, iv)));
        }
    }

    @Test
    void dekPayloadDecodeRoundtrip() {
        var vector = TestVectors.firstById("dekPayload", "dek-rsa");
        DekPayload dek = DekPayload.decode(vector.path("expected").asText());
        assertEquals("AES-256-GCM", dek.alg());
        assertArrayEquals(Codec.b64UrlDecode(vector.path("keyB64u").asText()), dek.key());
        assertArrayEquals(Codec.b64UrlDecode(vector.path("ivB64u").asText()), dek.iv());
    }

    @Test
    void dekPayloadDecodeRejectsMalformed() {
        assertThrows(WopSdkException.class, () -> DekPayload.decode(null));
        assertThrows(WopSdkException.class, () -> DekPayload.decode(""));
        assertThrows(WopSdkException.class, () -> DekPayload.decode("AES-256-GCM"));
        assertThrows(WopSdkException.class, () -> DekPayload.decode("AES-256-GCM$key"));             // 缺 iv
        assertThrows(WopSdkException.class, () -> DekPayload.decode("AES-256-GCM$key$iv$extra"));    // 段数
        assertThrows(WopSdkException.class, () -> DekPayload.decode("AES-256-GCM$ke+y$iv"));         // 非法 b64url
        assertThrows(WopSdkException.class, () -> DekPayload.decode("$key$iv"));                     // alg 空
    }

    // ==================== SignHeader ====================

    @Test
    void signHeaderBuildsStructuredValue() {
        String header = SignHeader.build("WOP-RSA3072-SHA256", 1800,
                List.of("x-wop-appkey", "x-wop-content-digest", "x-wop-nonce", "x-wop-timestamp"),
                "c2lnbmF0dXJl");
        assertEquals("WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-content-digest;x-wop-nonce;x-wop-timestamp/c2lnbmF0dXJl",
                header);
    }

    @Test
    void signHeaderParsesStructuredValue() {
        SignHeader.Parsed parsed = SignHeader.parse(
                "WOP-SM2-SM3 v1/60/x-wop-content-digest;x-wop-encrypt;x-wop-nonce;x-wop-timestamp/Si7Uw5eZm0Kii3Bu");
        assertEquals("WOP-SM2-SM3", parsed.securityReq());
        assertEquals("v1", parsed.protocolVersion());
        assertEquals(60, parsed.expiredSeconds());
        assertEquals(List.of("x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"),
                parsed.signedHeaders());
        assertEquals("Si7Uw5eZm0Kii3Bu", parsed.signature());
    }
    @Test
    void signHeaderRejectsMalformed() {
        assertThrows(WopSdkException.class, () -> SignHeader.parse(null));
        assertThrows(WopSdkException.class, () -> SignHeader.parse(""));
        assertThrows(WopSdkException.class, () -> SignHeader.parse("   "));
        // 缺空格分隔
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256v1/1800/a/b"));
        // 段数不足/超数
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/sig"));
        assertThrows(WopSdkException.class,
                () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a/b/extra"));
        // 协议版本
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v2/1800/a/b"));
        // expiredSeconds 非数字/非正
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/x/a/b"));
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/0/a/b"));
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/-5/a/b"));
        // signedHeaders 空段
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800//b"));
        // signature 空
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a/"));
        // 签名含 '/'（b64url 非法）
        assertThrows(WopSdkException.class, () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a/b/c"));
    }

    @Test
    void signHeaderAcceptsZeroPlusExpiredAndDedupSortsHeaders() {
        SignHeader.Parsed parsed = SignHeader.parse("WOP-RSA3072-SHA256 v1/1/x-wop-b;x-wop-a/sig");
        assertEquals(1, parsed.expiredSeconds());
        assertEquals(List.of("x-wop-b", "x-wop-a"), parsed.signedHeaders());
    }

    // ==================== EncryptHeader ====================

    @Test
    void encryptHeaderBuildsL2WithDek() {
        assertEquals("L2;dek=AAECAwQ", EncryptHeader.buildL2("AAECAwQ"));
    }

    @Test
    void encryptHeaderParsesL0AndL2() {
        EncryptHeader.Parsed l0 = EncryptHeader.parse("L0");
        assertEquals("L0", l0.level());
        assertNull(l0.dek());

        EncryptHeader.Parsed l2 = EncryptHeader.parse("L2;dek=AAECAwQ");
        assertEquals("L2", l2.level());
        assertEquals("AAECAwQ", l2.dek());
        assertTrue(l2.isEncrypted());
        assertNull(EncryptHeader.parse(null).dek());
        assertEquals("L0", EncryptHeader.parse(null).level());
    }

    @Test
    void encryptHeaderRejectsMalformed() {
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("L1"));
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("l0"));
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("L2"));                 // L2 缺 dek
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("L2;dek="));            // dek 空
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("L2;foo=abc"));         // 未知参数
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("L0;dek=abc"));         // L0 带 dek
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse("L2;dek=ab=c"));        // dek 带 = 
        assertThrows(WopSdkException.class, () -> EncryptHeader.parse(" L2;dek=abc "));       // 空白包裹
    }
}
