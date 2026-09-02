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

/**
 * WOP spec §2.1 / §2.2 / D14 符合性专测（条款 → 测试名反向核对矩阵锚点）。
 * 只测已有 main 代码路径，不为本测试新增任何生产分支。
 */
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

    // ==================== §2.1 必传 header（肯定式） ====================

    /** §2.1 肯定：L0 请求签名头声明的 signedHeaders 恰为五必传 header 的 L0 子集
     *  [x-wop-appkey, x-wop-nonce, x-wop-timestamp]。 */
    @Test
    // spec:2.1
    void l0SignedHeadersExactlyAppkeyNonceTimestamp() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-query", null, SecurityLevel.L0);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertEquals(Arrays.asList("x-wop-appkey", "x-wop-nonce", "x-wop-timestamp"), sign.signedHeaders());
        assertEquals(3, sign.signedHeaders().size());
    }

    /** §2.1 肯定：L2 请求 x-wop-encrypt 与 x-wop-content-digest 均入签。 */
    @Test
    // spec:2.1
    void l2SignedHeadersIncludeEncryptAndDigest() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-sync", Codec.utf8("{}"), SecurityLevel.L2);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(sign.signedHeaders().contains("x-wop-encrypt"), sign.signedHeaders().toString());
        assertTrue(sign.signedHeaders().contains("x-wop-content-digest"), sign.signedHeaders().toString());
    }

    // ==================== §2.1 必传 header（否定式） ====================

    /** §2.1 否定：L0 请求不得携带 x-wop-encrypt 头（该头为 L2 专属）。 */
    @Test
    // spec:2.1
    void l0RequestCarriesNoEncryptHeader() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("POST", "/gateway/waybill-query", Codec.utf8("{}"), SecurityLevel.L0);
        assertNull(draft.headers().get("x-wop-encrypt"));
    }

    /** §2.1 否定：无 body 时 x-wop-content-digest 缺席合法（D2 缺席语义，非缺陷）。 */
    @Test
    // spec:2.1
    void bodylessRequestDigestAbsentIsLegal() {
        RequestDraft draft = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB)
                .buildRequest("GET", "/gateway/waybill-query", null, SecurityLevel.L0);
        assertNull(draft.headers().get("x-wop-content-digest"));
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertFalse(sign.signedHeaders().contains("x-wop-content-digest"));
    }

    /** §2.1 否定：缺 appKey 构建失败，且归类 WopError.configuration（§2.2 路径）。 */
    @Test
    // spec:2.1 spec:2.2
    void missingAppKeyThrowsConfiguration() {
        WopError ex = assertThrows(WopError.class, () -> WopClient.builder()
                .suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV)
                .platformPublicKey(RSA_PUB)
                .build());
        assertEquals(WopError.Category.configuration, ex.category());
        assertTrue(ex.getMessage().contains("appKey"));
    }

    // ==================== §2.2 WopError 闭集 ====================

    /** §2.2 肯定：Category 闭集恰为 7 值且顺序稳定（小写 ASCII，跨语言恒定）。 */
    @Test
    // spec:2.2
    void categoryClosedSetExactlySevenValues() {
        assertEquals(7, WopError.Category.values().length);
        assertEquals(Arrays.asList(
                        WopError.Category.configuration, WopError.Category.parse,
                        WopError.Category.unsupported, WopError.Category.integrity,
                        WopError.Category.consistency, WopError.Category.signature,
                        WopError.Category.decrypt),
                Arrays.asList(WopError.Category.values()));
        // 小写 ASCII 保证：name() 即线上 category 串
        assertEquals("configuration", WopError.Category.configuration.name());
        assertEquals("decrypt", WopError.Category.decrypt.name());
    }

    /** §2.2 路径：协议解析错误 → Category.parse（SignHeader 坏输入）。 */
    @Test
    // spec:2.2
    void signHeaderParseErrorsMapToParse() {
        WopError ex = assertThrows(WopError.class,
                () -> SignHeader.parse("WOP-RSA3072-SHA256 v1/1800/a;;b/c2ln"));
        assertEquals(WopError.Category.parse, ex.category());
    }

    /** §2.2 路径：buildRequest 参数错误 → Category.configuration。 */
    @Test
    // spec:2.2
    void buildRequestArgumentErrorsMapToConfiguration() {
        WopClient client = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        WopError ex = assertThrows(WopError.class,
                () -> client.buildRequest("POST", "  ", Codec.utf8("{}"), SecurityLevel.L0));
        assertEquals(WopError.Category.configuration, ex.category());
    }

    // ==================== D14 userId 贯通 ====================

    /** D14 肯定：SM2 出向签名 userId 与请求身份 appKey 同源——网关侧以 appKey 为
     *  userId 验签必须通过（复用 WopClientBuildRequestTest.signatureVerifies 四参模式）。 */
    @Test
    // spec:D14
    void sm2OutboundSignatureVerifiesWithAppKeyUserId() {
        WopClient client = fixedClient("WOP-SM2-SM3", SM2_PRIV, SM2_PUB);
        RequestDraft draft = client.buildRequest("POST", "/gateway/waybill-sync",
                Codec.utf8("{\"sm\":true}"), SecurityLevel.L2);
        SignHeader.Parsed sign = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(WopClientBuildRequestTest.signatureVerifies(draft, sign, SM2_PUB),
                "userId=appKey 时 SM2 出向签名必须验证通过");
        assertEquals("app_001", draft.headers().get("x-wop-appkey"));
    }

    /** D14 否定：同一 SM2 出向签名改用协议固定值（≠appKey） 验签失败——证明出向签名绑定的是
     *  appKey 而非固定 userId（若误用固定值，此断言必失败）。 */
    @Test
    // spec:D14
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

        // 以协议固定值（≠appKey）验签：ZA 计算错位 → 必须失败
        assertFalse(AlgorithmSuite.parse(sign.securityReq()).signature().verify(
                Codec.utf8(canonical), Codec.b64UrlDecode(sign.signature()), merchantPub,
                Codec.utf8("1234567812345678")),
                "同一签名用非 appKey userId 验签必须失败（证明 userId 实为 appKey）");
    }
}
