package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.*;
import com.wanlianyida.wop.crypto.strategies.CipherResult;
import io.cucumber.java.zh_cn.假如;
import io.cucumber.java.zh_cn.当;
import io.cucumber.java.zh_cn.那么;
import io.cucumber.java.zh_cn.而且;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * WOP 商户 SDK 使用场景（spec v1.0）Gherkin 步骤定义。
 * 复用黄金向量密钥（TestVectors）与平台响应装配（PlatformRig 模式）。
 */
public class WopSdkSteps {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private WopClient client;
    private RequestDraft draft;
    private VerifyResult verify;
    private RuntimeException lastError;
    private AlgorithmSuite parsedSuite;
    private final List<String> nonceTrack = new ArrayList<>();

    private static final String PATH = "/gateway/waybill-query";
    private static final String SYNC_PATH = "/gateway/waybill-sync";
    private static final byte[] BODY = "{\"orderNo\":\"WLYD001\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESPONSE = "{\"waybillNo\":\"YD001\",\"status\":\"OK\"}".getBytes(StandardCharsets.UTF_8);

    private static WopClient client(String suiteName, String priv, String pub, Supplier<String> nonce, LongSupplier clock) {
        return new WopClient(new WopClient.Config("app_001", AlgorithmSuite.parse(suiteName), priv, pub, 1800),
                clock, nonce);
    }

    private static WopClient fixedClient(String suiteName, String priv, String pub) {
        return client(suiteName, priv, pub, () -> "fixed00000000000000000000000000a", () -> 1_758_900_000_000L);
    }

    private WopClient randomClient(String suiteName, String priv, String pub) {
        return client(suiteName, priv, pub, () -> {
            byte[] b = new byte[16];
            new java.security.SecureRandom().nextBytes(b);
            String h = Codec.hexLower(b);
            nonceTrack.add(h);
            return h;
        }, System::currentTimeMillis);
    }

    // ==================== 背景 ====================

    @假如("商户持有 WOP-RSA3072-SHA256 套件的商户私钥与平台公钥")
    public void merchantHasKeys() {
        client = randomClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
    }

    @假如("应用 appKey 为 app_001")
    public void appKey() {
    }

    @假如("签名字段到期窗口为 1800 秒")
    public void expiredSeconds() {
    }

    // ==================== 出向构建 ====================

    @当("^构建 L0 请求 GET /gateway/waybill-query 无 body$")
    public void buildL0GetNoBody() {
        draft = client.buildRequest("GET", PATH, null, SecurityLevel.L0);
    }

    @当("^构建 L0 请求 POST /gateway/waybill-sync body 为 业务报文$")
    public void buildL0PostWithBody() {
        draft = client.buildRequest("POST", SYNC_PATH, BODY, SecurityLevel.L0);
    }

    @当("^构建 L2 请求 POST /gateway/waybill-sync body 为 业务报文$")
    public void buildL2PostWithBody() {
        draft = client.buildRequest("POST", SYNC_PATH, BODY, SecurityLevel.L2);
    }

    @当("^构建 L0 请求 \"([^\"]*)\" /gateway/waybill-query body 为 业务报文$")
    public void buildL0MixedCase(String method) {
        draft = client.buildRequest(method, PATH, BODY, SecurityLevel.L0);
    }

    @当("构建 L0 请求 空方法")
    public void buildEmptyMethod() {
        attempt(() -> client.buildRequest("  ", PATH, BODY, SecurityLevel.L0));
    }

    @当("构建 L0 请求 空路径")
    public void buildEmptyPath() {
        attempt(() -> client.buildRequest("POST", "  ", BODY, SecurityLevel.L0));
    }

    @当("构建 L2 请求 无 body")
    public void buildL2NoBody() {
        attempt(() -> client.buildRequest("POST", PATH, null, SecurityLevel.L2));
    }

    @当("使用 SM2-SM3 套件构建 L2 请求 body 为 业务报文")
    public void buildL2Sm2() {
        var sm2Priv = TestVectors.keys("sm2").path("privateDB64").asText();
        var sm2Pub = TestVectors.keys("sm2").path("publicPointB64").asText();
        client = randomClient("WOP-SM2-SM3", sm2Priv, sm2Pub);
        draft = client.buildRequest("POST", SYNC_PATH, BODY, SecurityLevel.L2);
    }

    // ==================== 出向断言 ====================

    @那么("请求无 x-wop-content-digest 头")
    public void noDigestHeader() {
        assertNull(draft.headers().get("x-wop-content-digest"));
    }

    @那么("请求包含 appkey、timestamp、nonce、sign 头")
    public void hasBaseHeaders() {
        assertNotNull(draft.headers().get("x-wop-appkey"));
        assertNotNull(draft.headers().get("x-wop-timestamp"));
        assertNotNull(draft.headers().get("x-wop-nonce"));
        assertNotNull(draft.headers().get("x-wop-sign"));
    }

    @那么("签名头包含 appkey、timestamp、nonce")
    public void signedContainsBase() {
        SignHeader.Parsed parsed = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(parsed.signedHeaders().containsAll(List.of("x-wop-appkey", "x-wop-timestamp", "x-wop-nonce")));
    }

    @那么("请求含 x-wop-content-digest 头且为 {string}")
    public void digestHeaderFormat(String pattern) {
        String digest = draft.headers().get("x-wop-content-digest");
        assertNotNull(digest);
        assertTrue(digest.matches("sha-256 [0-9a-f]{64}"), "digest 格式: " + digest);
    }

    @那么("签名头包含 x-wop-content-digest")
    public void signedContainsDigest() {
        SignHeader.Parsed parsed = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(parsed.signedHeaders().contains("x-wop-content-digest"));
    }

    @那么("wireBody 与业务报文一致")
    public void wireBodyEqualsBody() {
        assertArrayEquals(BODY, draft.wireBody());
    }

    @那么("请求含 x-wop-encrypt 头且以 {string} 开头")
    public void encryptHeaderPrefix(String prefix) {
        String enc = draft.headers().get("x-wop-encrypt");
        assertNotNull(enc);
        assertTrue(enc.startsWith(prefix), "encrypt 头: " + enc);
    }

    @那么("wireBody 为 密文信封")
    public void wireBodyEnvelope() {
        assertNotNull(draft.wireBody());
        assertTrue(new String(draft.wireBody(), StandardCharsets.UTF_8).contains("\"encrypted\""));
    }

    @那么("签名头包含 x-wop-encrypt 与 x-wop-content-digest")
    public void signedContainsEncryptAndDigest() {
        SignHeader.Parsed parsed = SignHeader.parse(draft.headers().get("x-wop-sign"));
        assertTrue(parsed.signedHeaders().containsAll(List.of("x-wop-encrypt", "x-wop-content-digest")));
    }

    @那么("digest 是对密文 wireBody 的摘要（非明文）")
    public void digestIsOfWireBody() {
        String digest = draft.headers().get("x-wop-content-digest");
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
        assertEquals("sha-256 " + Codec.hexLower(suite.digest().digest(draft.wireBody())), digest);
        assertNotEquals("sha-256 " + Codec.hexLower(suite.digest().digest(BODY)), digest);
    }

    @那么("请求方法规范化为 POST")
    public void methodNormalized() {
        assertEquals("POST", draft.method());
    }

    @那么("抛出配置类异常")
    public void configurationErrorThrown() {
        assertNotNull(lastError, "应抛出配置类异常");
        assertTrue(lastError.getMessage().contains("为空") || lastError.getMessage().contains("需要非空")
                        || lastError.getMessage().contains("密钥"),
                "配置类错误: " + lastError.getMessage());
    }

    @那么("抛出配置类异常（L2 需要非空 body）")
    public void configurationErrorL2() {
        configurationErrorThrown();
    }

    // ==================== 入向校验 ====================

    @当("平台返回 L0 响应 响应报文")
    public void platformL0Response() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond(PATH, RESPONSE, false);
        verify = client.verifyResponse(resp.headers(), resp.wire(), PATH);
    }

    @当("平台返回 L2 响应 响应报文")
    public void platformL2Response() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond(PATH, RESPONSE, true);
        verify = client.verifyResponse(resp.headers(), resp.wire(), PATH);
    }

    @当("平台返回 L0 响应 响应报文 但签名被篡改")
    public void platformTamperedResponse() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond(PATH, RESPONSE, false);
        String sig = resp.headers().get("x-wop-sign");
        char[] cs = sig.toCharArray();
        int pos = cs.length - 10;
        cs[pos] = (cs[pos] == 'A') ? 'B' : 'A';  // 合法 base64url 字符替换，格式不变
        resp.headers().put("x-wop-sign", new String(cs));
        verify = client.verifyResponse(resp.headers(), resp.wire(), PATH);
    }

    @当("^平台回调 POST /callback/waybill-status 带 L2 报文$")
    public void platformCallback() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond("/callback/waybill-status", RESPONSE, true);
        verify = client.verifyCallback(resp.headers(), resp.wire(), "/callback/waybill-status");
    }

    @当("平台返回 L0 响应 响应报文 但 digest 头缺席")
    public void platformNoDigest() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond(PATH, RESPONSE, false);
        resp.headers().remove("x-wop-content-digest");
        verify = client.verifyResponse(resp.headers(), resp.wire(), PATH);
    }

    @当("平台返回无 body 的 L0 响应 但带 digest 头")
    public void platformDigestWithoutBody() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond(PATH, new byte[0], false);
        Map<String, String> h = new LinkedHashMap<>(resp.headers());
        h.put("x-wop-content-digest", "sha-256 " + Codec.hexLower(
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").digest().digest(RESPONSE)));
        verify = client.verifyResponse(h, new byte[0], PATH);
    }

    @当("平台返回 L0 响应 响应报文 但 digest 值错误")
    public void platformWrongDigest() {
        var rig = new PlatformRig("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        var resp = rig.respond(PATH, RESPONSE, false);
        resp.headers().put("x-wop-content-digest", "sha-256 " + "0".repeat(64));
        verify = client.verifyResponse(resp.headers(), resp.wire(), PATH);
    }

    @那么("校验结果 ok 为 true 且明文与原始业务响应一致")
    public void verifyOkPlaintext() {
        assertTrue(verify.ok(), "校验应通过: " + verify.reason());
        assertArrayEquals(RESPONSE, verify.plaintext());
    }

    @那么("校验结果 ok 为 false 且错误为签名失败模糊文案（不泄露细节）")
    public void verifyFuzzySignature() {
        assertFalse(verify.ok());
        assertEquals(VerifyResult.Reason.SIGNATURE_FAILED, verify.reason());
        assertNull(verify.detail(), "模糊错误不应泄露细节");
    }

    @那么("校验结果 ok 为 true 且明文与回调业务报文一致")
    public void verifyCallbackOk() {
        assertTrue(verify.ok(), "回调校验应通过: " + verify.reason());
        assertArrayEquals(RESPONSE, verify.plaintext());
    }

    @那么("校验结果 ok 为 false 且错误为缺失摘要头")
    public void verifyMissingDigest() {
        assertFalse(verify.ok());
        assertEquals(VerifyResult.Reason.MISSING_DIGEST_HEADER, verify.reason());
    }

    @那么("校验结果 ok 为 false 且错误为摘要头非法")
    public void verifyInvalidDigest() {
        assertFalse(verify.ok());
        assertTrue(verify.reason() == VerifyResult.Reason.INVALID_DIGEST_HEADER
                || verify.reason() == VerifyResult.Reason.MISSING_SIGNED_HEADER, "reason: " + verify.reason());
    }

    @那么("校验结果 ok 为 false 且错误为签名失败（F6 先验签）")
    public void verifyDigestMismatch() {
        assertFalse(verify.ok());
        assertEquals(VerifyResult.Reason.SIGNATURE_FAILED, verify.reason());
    }

    // ==================== 套件与格式 ====================

    @当("解析套件 {string}（跨族）")
    public void parseCrossFamily(String suite) {
        attemptParse(suite);
    }

    @当("解析套件 {string}")
    public void parseSuite(String suite) {
        attemptParse(suite);
    }

    private void attemptParse(String suite) {
        try {
            parsedSuite = AlgorithmSuite.parse(suite);
            lastError = null;
        } catch (RuntimeException e) {
            lastError = e;
        }
    }

    @那么("抛出套件解析异常")
    public void suiteParseError() {
        assertNotNull(lastError);
        assertTrue(lastError.getMessage().contains("套件") || lastError.getMessage().contains("不支持"),
                "套件错误: " + lastError.getMessage());
    }

    @那么("抛出套件不支持异常")
    public void suiteUnsupportedError() {
        assertNotNull(lastError);
        assertTrue(lastError.getMessage().contains("套件") || lastError.getMessage().contains("不支持"),
                "套件错误: " + lastError.getMessage());
    }

    @那么("请求成功且 encrypt 头格式合法")
    public void sm2RequestOk() {
        assertNotNull(draft);
        assertNotNull(draft.headers().get("x-wop-encrypt"));
        assertTrue(draft.headers().get("x-wop-encrypt").startsWith("L2;dek="));
    }

    @当("解码 base64url 字符串 {string}（带填充）")
    public void decodeB64WithPadding(String s) {
        attemptDecode(s);
    }

    @当("解码 base64url 字符串 {string}（标准 base64 字符）")
    public void decodeB64StandardChars(String s) {
        attemptDecode(s);
    }

    private void attemptDecode(String s) {
        try {
            Codec.b64UrlDecode(s);
            lastError = null;
        } catch (IllegalArgumentException e) {
            lastError = e;
        }
    }

    @那么("抛出非法输入异常")
    public void invalidInputError() {
        assertNotNull(lastError);
        assertTrue(lastError.getMessage().contains("base64url"), "解码错误: " + lastError.getMessage());
    }

    // ==================== 密钥与防重放 ====================

    @当("分别用 PEM 与 Base64 单行格式构建两个客户端")
    public void pemAndBase64Clients() {
        String pemPriv = pemWrap(RSA_PRIV, "PRIVATE KEY");
        String pemPub = pemWrap(RSA_PUB, "PUBLIC KEY");
        WopClient pem = fixedClient("WOP-RSA3072-SHA256", pemPriv, pemPub);
        WopClient b64 = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        RequestDraft a = pem.buildRequest("POST", PATH, BODY, SecurityLevel.L0);
        RequestDraft b = b64.buildRequest("POST", PATH, BODY, SecurityLevel.L0);
        assertEquals(a.headers().get("x-wop-sign"), b.headers().get("x-wop-sign"));
    }

    @那么("两者构建同一请求的签名头一致")
    public void signaturesIdentical() {
    }

    @当("构建客户端 私钥为 {string}")
    public void buildClientBadKey(String key) {
        try {
            client = fixedClient("WOP-RSA3072-SHA256", key, RSA_PUB);
            lastError = null;
        } catch (WopError e) {
            lastError = e;
        }
    }

    @那么("nonce 为 32 位小写 hex 且每次不同")
    public void nonceFormat() {
        String nonce = draft.headers().get("x-wop-nonce");
        assertTrue(nonce.matches("[0-9a-f]{32}"), "nonce: " + nonce);
        if (nonceTrack.size() > 1) {
            assertEquals(nonceTrack.size(), new HashSet<>(nonceTrack).size(), "nonce 不应重复");
        }
    }

    @那么("timestamp 为毫秒级时间戳")
    public void timestampMs() {
        long ts = Long.parseLong(draft.headers().get("x-wop-timestamp"));
        assertTrue(ts > 1_700_000_000_000L && ts < 2_000_000_000_000L, "毫秒级: " + ts);
    }

    @当("用固定 nonce 与固定 timestamp 构建两次相同 L0 请求")
    public void buildTwiceFixed() {
        WopClient fixed = fixedClient("WOP-RSA3072-SHA256", RSA_PRIV, RSA_PUB);
        RequestDraft a = fixed.buildRequest("POST", PATH, BODY, SecurityLevel.L0);
        RequestDraft b = fixed.buildRequest("POST", PATH, BODY, SecurityLevel.L0);
        assertEquals(a.headers().get("x-wop-sign"), b.headers().get("x-wop-sign"));
        assertArrayEquals(a.wireBody(), b.wireBody());
    }

    @那么("两次请求的 sign 头字节一致")
    public void deterministicSign() {
    }

    // ==================== 辅助 ====================

    private static String pemWrap(String b64, String label) {
        StringBuilder sb = new StringBuilder("-----BEGIN " + label + "-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END " + label + "-----");
        return sb.toString();
    }

    private void attempt(Runnable r) {
        try {
            r.run();
            lastError = null;
        } catch (WopError e) {
            lastError = e;
        }
    }

    /** 平台响应装配（模拟网关侧：平台私钥签名 + L2 信封）。 */
    private record PlatformRig(String securityReq, String platformPrivB64, String merchantPubB64) {
        PlatformResponse respond(String path, byte[] plain, boolean l2) {
            AlgorithmSuite suite = AlgorithmSuite.parse(securityReq);
            PrivateKey platformPriv = KeyCodec.parsePrivateKey(platformPrivB64, suite);
            PublicKey merchantPub = KeyCodec.parsePublicKey(merchantPubB64, suite);

            byte[] wire = plain;
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("x-wop-timestamp", "1758900000000");
            headers.put("x-wop-nonce", "platformnonce0000000000000000001");
            if (l2) {
                byte[] dek = new byte[suite.messageEncrypt().keyLength()];
                new java.security.SecureRandom().nextBytes(dek);
                CipherResult result = suite.messageEncrypt().encrypt(plain, dek);
                wire = EncryptedEnvelope.wrap(Codec.b64UrlEncode(result.cipher()));
                String payload = DekPayload.encode(new DekPayload(suite.expectedDekAlg(), dek, result.iv()));
                byte[] wrapped = suite.keyEncrypt().encrypt(Codec.utf8(payload), merchantPub);
                headers.put("x-wop-encrypt", EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
            }
            if (wire != null && wire.length > 0) {
                headers.put("x-wop-content-digest", ContentDigest.build(suite, wire));
            }
            List<String> signed = new ArrayList<>();
            if (headers.containsKey("x-wop-content-digest")) signed.add("x-wop-content-digest");
            if (headers.containsKey("x-wop-encrypt")) signed.add("x-wop-encrypt");
            signed.add("x-wop-nonce");
            signed.add("x-wop-timestamp");
            signed.sort(String::compareTo);
            Map<String, String> sub = new TreeMap<>();
            signed.forEach(n -> sub.put(n, headers.get(n)));
            String canonical = CanonicalRequest.build("v1/1800", "POST", path, "",
                    CanonicalRequest.canonicalHeaders(sub));
            byte[] sig = suite.signature().sign(Codec.utf8(canonical), platformPriv, Codec.utf8("1234567812345678"));
            headers.put("x-wop-sign", SignHeader.build(suite.securityReq(), 1800, signed, Codec.b64UrlEncode(sig)));
            return new PlatformResponse(headers, wire);
        }
    }

    private record PlatformResponse(Map<String, String> headers, byte[] wire) {
    }
}
