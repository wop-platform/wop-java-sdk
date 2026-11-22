package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.CanonicalRequest;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.KeyCodec;
import com.wanlianyida.wop.crypto.SignHeader;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WopSpecConformanceTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String SM2_PRIV = TestVectors.keys("sm2").path("privateDB64").asText();
    private static final String SM2_PUB = TestVectors.keys("sm2").path("publicPointB64").asText();

    private static final LongSupplier CLOCK = () -> 1_758_900_000_000L;
    private static final Supplier<String> NONCE = () -> "fixed00000000000000000000000000a";

    private static WopClient fixedClient(String suite, String priv, String pub) {
        return new WopClient(new WopClient.Config(
                "app_001", AlgorithmSuite.parse(suite), priv, pub, 1800), CLOCK, NONCE);
    }


    @Test
    void l0SignedHeadersExactlyAppkeyNonceTimestamp() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-query", null, SecurityLevel.L0);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(Arrays.asList("x-wop-appkey", "x-wop-nonce", "x-wop-timestamp"), sign.signedHeaders());
        assertEquals(3, sign.signedHeaders().size());
    }

    @Test
    void l2SignedHeadersIncludeEncryptAndDigest() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-sync", Codec.utf8("{}"), SecurityLevel.L2);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-encrypt"), sign.signedHeaders().toString());
        assertTrue(sign.signedHeaders().contains("x-wop-content-digest"), sign.signedHeaders().toString());
    }

    @Test
    void subMchIdHeaderMustBeSignedWhenCarried() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-sync", Codec.utf8("{}"), SecurityLevel.L0,
                        WopRequestOptions.builder().subMchId("PLF-SUB-001").build());
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-sub-mch-id"), sign.signedHeaders().toString());
        assertTrue(WopClientBuildRequestTest.signatureVerifies(draft, sign, RSA_PUB));
    }


    @Test
    void l0RequestCarriesNoEncryptHeader() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-query", Codec.utf8("{}"), SecurityLevel.L0);
        assertNull(draft.headers().get("x-wop-encrypt"));
    }

    @Test
    void bodylessRequestDigestAbsentIsLegal() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("GET", "/gateway/waybill-query", null, SecurityLevel.L0);
        assertNull(draft.headers().get("x-wop-content-digest"));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertFalse(sign.signedHeaders().contains("x-wop-content-digest"));
    }

    @Test
    void missingAppKeyThrowsConfiguration() {
        WopError ex = assertThrows(WopError.class, () -> WopClient.builder()
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .build());
        assertEquals(WopError.Category.configuration, ex.category());
        assertTrue(ex.getMessage().contains("appKey"));
    }


    @Test
    void categoryClosedSetExactlySevenValues() {
        assertEquals(7, WopError.Category.values().length);
        assertEquals(Arrays.asList(
                        WopError.Category.configuration, WopError.Category.parse,
                        WopError.Category.unsupported, WopError.Category.integrity,
                        WopError.Category.consistency, WopError.Category.signature,
                        WopError.Category.decrypt),
                Arrays.asList(WopError.Category.values()));
        assertEquals("configuration", WopError.Category.configuration.name());
        assertEquals("decrypt", WopError.Category.decrypt.name());
    }

    @Test
    void signHeaderParseErrorsMapToParse() {
        WopError ex = assertThrows(WopError.class,
                () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a;;b/c2ln"));
        assertEquals(WopError.Category.parse, ex.category());
    }

    @Test
    void buildRequestArgumentErrorsMapToConfiguration() {
        WopClient client = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        WopError ex = assertThrows(WopError.class,
                () -> client.buildRequest("POST", "  ", Codec.utf8("{}"), SecurityLevel.L0));
        assertEquals(WopError.Category.configuration, ex.category());
    }


    @Test
    void sm2OutboundSignatureVerifiesWithAppKeyUserId() {
        WopClient client = fixedClient("WOP-SM2-SM3", SM2_PRIV, SM2_PUB);
        RequestDraft draft = client.buildRequest("POST", "/gateway/waybill-sync",
                Codec.utf8("{\"sm\":true}"), SecurityLevel.L2);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(WopClientBuildRequestTest.signatureVerifies(draft, sign, SM2_PUB),
                "userId=appKey 时 SM2 出向签名必须验证通过");
        assertEquals("app_001", draft.headers().get("x-wop-appkey"));
    }

    @Test
    void sm2OutboundSignatureFailsWithForeignUserId() {
        WopClient client = fixedClient("WOP-SM2-SM3", SM2_PRIV, SM2_PUB);
        RequestDraft draft = client.buildRequest("POST", "/gateway/waybill-sync",
                Codec.utf8("{\"sm\":true}"), SecurityLevel.L2);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));

        PublicKey merchantPub = KeyCodec.parsePublicKey(SM2_PUB,
                AlgorithmSuite.parse(sign.securityReq()));
        Map<String, String> lower = new LinkedHashMap<>();
        draft.headers().forEach((k, v) -> lower.put(k.toLowerCase(java.util.Locale.ROOT), v));
        Map<String, String> signed = new TreeMap<>();
        for (String name : sign.signedHeaders()) {
            signed.put(name, lower.get(name));
        }
        String canonical = CanonicalRequest.build(
                sign.protocolVersion() + "/" + sign.expiredSeconds(),
                draft.method(), draft.path(), "", CanonicalRequest.canonicalHeaders(signed));

        assertFalse(AlgorithmSuite.parse(sign.securityReq()).signature().verify(
                Codec.utf8(canonical), Codec.b64UrlDecode(sign.signature()), merchantPub,
                Codec.utf8("1234567812345678")),
                "同一签名用非 appKey userId 验签必须失败（证明 userId 实为 appKey）");
    }
}
