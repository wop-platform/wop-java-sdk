package com.wanlianyida.wop.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.wanlianyida.wop.WopError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtocolHeaderTest {

    /** 解析类失败：类型 WopError + category=parse 双重断言（spec:2.2）。 */
    private static WopError parseError(Executable exec) {
        WopError e = assertThrows(WopError.class, exec);
        assertEquals(WopError.Category.parse, e.category());
        return e;
    }


    @Test
    void dekPayloadEncodeMatchesGoldenVectors() {
        for (String id : new String[]{"dek-rsa", "dek-sm2"}) {
            JsonNode vector = TestVectors.firstById("dekPayload", id);
            byte[] key = Codec.b64UrlDecode(vector.path("keyB64u").asText());
            byte[] iv = Codec.b64UrlDecode(vector.path("ivB64u").asText());
            assertEquals(vector.path("expected").asText(),
                    DekPayload.encode(new DekPayload(vector.path("alg").asText(), key, iv)));
        }
    }

    @Test
    void dekPayloadDecodeRoundtrip() {
        JsonNode vector = TestVectors.firstById("dekPayload", "dek-rsa");
        DekPayload dek = DekPayload.decode(vector.path("expected").asText());
        assertEquals("AES-256-GCM", dek.alg());
        assertArrayEquals(Codec.b64UrlDecode(vector.path("keyB64u").asText()), dek.key());
        assertArrayEquals(Codec.b64UrlDecode(vector.path("ivB64u").asText()), dek.iv());
    }

    @Test
    void dekPayloadDecodeRejectsMalformed() {
        parseError(() -> DekPayload.decode(null));
        parseError(() -> DekPayload.decode(""));
        parseError(() -> DekPayload.decode("AES-256-GCM"));
        parseError(() -> DekPayload.decode("AES-256-GCM$key"));
        parseError(() -> DekPayload.decode("AES-256-GCM$key$iv$extra"));
        parseError(() -> DekPayload.decode("AES-256-GCM$ke+y$iv"));
        parseError(() -> DekPayload.decode("$key$iv"));
    }


    @Test
    void signHeaderBuildsStructuredValue() {
        String header = SignHeader.build("WOP-RSA3072-SHA256", 1800,
                Arrays.asList("x-wop-appkey", "x-wop-content-digest", "x-wop-nonce", "x-wop-timestamp"),
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
        assertEquals(Arrays.asList("x-wop-content-digest", "x-wop-encrypt", "x-wop-nonce", "x-wop-timestamp"),
                parsed.signedHeaders());
        assertEquals("Si7Uw5eZm0Kii3Bu", parsed.signature());
    }
    @Test
    void signHeaderRejectsMalformed() {
        parseError(() -> SignHeader.parse(null));
        parseError(() -> SignHeader.parse(""));
        parseError(() -> SignHeader.parse("   "));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256v1/1800/a/b"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/sig"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a/b/extra"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v2/1800/a/b"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/x/a/b"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/0/a/b"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/-5/a/b"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800//b"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a/"));
        parseError(() -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a/b/c"));
    }

    @Test
    void signHeaderAcceptsZeroPlusExpiredAndDedupSortsHeaders() {
        SignHeader.Parsed parsed = SignHeader.parse("WOP-RSA3072-SHA256 v1/1/x-wop-b;x-wop-a/sig");
        assertEquals(1, parsed.expiredSeconds());
        assertEquals(Arrays.asList("x-wop-b", "x-wop-a"), parsed.signedHeaders());
    }


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
        parseError(() -> EncryptHeader.parse("L1"));
        parseError(() -> EncryptHeader.parse("l0"));
        parseError(() -> EncryptHeader.parse("L2"));
        parseError(() -> EncryptHeader.parse("L2;dek="));
        parseError(() -> EncryptHeader.parse("L2;foo=abc"));
        parseError(() -> EncryptHeader.parse("L0;dek=abc"));
        parseError(() -> EncryptHeader.parse("L2;dek=ab=c"));
        parseError(() -> EncryptHeader.parse(" L2;dek=abc "));
    }
}
