package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.CanonicalRequest;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.ContentDigest;
import com.wanlianyida.wop.crypto.DekPayload;
import com.wanlianyida.wop.crypto.EncryptedEnvelope;
import com.wanlianyida.wop.crypto.EncryptHeader;
import com.wanlianyida.wop.crypto.KeyCodec;
import com.wanlianyida.wop.crypto.SignHeader;
import com.wanlianyida.wop.crypto.TestVectors;
import com.wanlianyida.wop.crypto.strategies.Aes256GcmStrategy;
import com.wanlianyida.wop.crypto.strategies.CipherResult;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 故障注入（协议层）：在"格式全部合法"的载体上注入传输/对端故障形态，
 * 断言失败传播符合 I7（模糊类无细节）与 F6 顺序语义。
 */
class FaultInjectionTest {

    private static final String MERCHANT_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String MERCHANT_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
    private static final String PLATFORM_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();

    private static final AlgorithmSuite RSA = AlgorithmSuite.parse("WOP-RSA3072-SHA256");

    private final WopClient client = WopClient.builder()
            .appKey("app_fault").suite("WOP-RSA3072-SHA256")
            .merchantPrivateKey(MERCHANT_PRIV).platformPublicKey(MERCHANT_PUB)
            .build();

    /** 平台响应拼装（与 WopClientVerifyTest 同构的紧凑版）。 */
    private Map<String, String> platformResponse(String path, byte[] plain, boolean l2,
                                                 java.util.function.BiFunction<byte[], String, byte[]> wireMutator) {
        try {
            PrivateKey platformPriv = KeyCodec.parsePrivateKey(PLATFORM_PRIV, RSA);
            PublicKey merchantPub = KeyCodec.parsePublicKey(MERCHANT_PUB, RSA);

            byte[] wire = plain;
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("x-wop-timestamp", "1758900000000");
            headers.put("x-wop-nonce", "faultnonce00000000000000000001");

            if (l2) {
                byte[] dek = new byte[RSA.messageEncrypt().keyLength()];
                new SecureRandom().nextBytes(dek);
                CipherResult result = RSA.messageEncrypt().encrypt(plain, dek);
                wire = EncryptedEnvelope.wrap(Codec.b64UrlEncode(result.cipher()));
                String payload = DekPayload.encode(new DekPayload(RSA.expectedDekAlg(), dek, result.iv()));
                headers.put("x-wop-encrypt", EncryptHeader.buildL2(Codec.b64UrlEncode(
                        RSA.keyEncrypt().encrypt(Codec.utf8(payload), merchantPub))));
            }
            // 故障注入点：对 wire 做变异（如截断），再按变异后的 wire 计算 digest（保证签名/摘要层通过）
            if (wireMutator != null) {
                wire = wireMutator.apply(wire, path);
            }
            headers.put("x-wop-content-digest", ContentDigest.build(RSA, wire));

            List<String> signed = new ArrayList<>(headers.keySet());
            signed.remove("x-wop-sign");
            signed.sort(String::compareTo);
            Map<String, String> sub = new TreeMap<>();
            signed.forEach(n -> sub.put(n, headers.get(n)));
            String canonical = CanonicalRequest.build("v1/1800", "POST", path, "",
                    CanonicalRequest.canonicalHeaders(sub));
            headers.put("x-wop-sign", SignHeader.build("WOP-RSA3072-SHA256", 1800, signed,
                    Codec.b64UrlEncode(RSA.signature().sign(Codec.utf8(canonical), platformPriv,
                            Codec.utf8("1234567812345678")))));

            headers.put("__wire__", Codec.b64UrlEncode(wire));   // 回传构造出的 wire 给测试
            return headers;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] wireOf(Map<String, String> headers) {
        return Codec.b64UrlDecode(headers.remove("__wire__"));
    }

    @Test
    void corruptedCiphertextInsideEnvelopeFailsVaguely() {
        // 故障：信封结构完整但 encrypted 段内单字符被改（中间层重写/编码损伤）——
        // digest/签名按损伤后重算，直达 GCM tag 校验 → 解密失败（模糊）
        Map<String, String> headers = platformResponse("/p", Codec.utf8("payload"), true,
                FaultInjectionTest::flipOneCipherChar);
        byte[] wire = wireOf(headers);
        VerifyResult result = client.verifyResponse(headers, wire, "/p");
        assertEquals(VerifyResult.Reason.DECRYPT_FAILED, result.reason());
        assertEquals("解密失败", result.message());   // tag 不匹配细节不泄露
    }

    @Test
    void truncatedEnvelopeFailsExplicitly() {
        // 故障：传输截断砍掉信封 JSON 闭括号——结构层损伤属公开可判定 → 解析类明确拒绝
        Map<String, String> headers = platformResponse("/p", Codec.utf8("payload"), true,
                (wire, p) -> Arrays.copyOf(wire, wire.length - 1));
        byte[] wire = wireOf(headers);
        VerifyResult result = client.verifyResponse(headers, wire, "/p");
        assertEquals(VerifyResult.Reason.INVALID_ENCRYPTED_BODY, result.reason());
    }

    /** 信封 encrypted 段内翻转一个 base64url 字符（保持长度与字母表合法性）。 */
    private static byte[] flipOneCipherChar(byte[] wire, String ignored) {
        int start = "{\"encrypted\":\"".length();
        for (int i = start; i < wire.length - 2; i++) {
            char c = (char) wire[i];
            if (c == '"') {
                break;   // 到达密文段结尾
            }
            if (c >= 'A' && c < 'Z') {
                wire[i] = (byte) (c + 1);
                return wire;
            }
        }
        throw new IllegalStateException("未找到可翻转字符");
    }

    @Test
    void dekKeyLengthCorruptionFailsVaguely() {
        // 故障：DEK 载荷 key 段长度畸形（31B）——alg 正确、解包成功，bulk 解密抛错归入模糊
        byte[] plain = Codec.utf8("payload");
        byte[] dek = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        byte[] iv = Codec.b64UrlDecode(TestVectors.input("aesIvB64u"));
        byte[] wire = EncryptedEnvelope.wrap(Codec.b64UrlEncode(
                Aes256GcmStrategy.INSTANCE.encrypt(plain, dek).cipher()));

        try {
            PublicKey merchantPub = KeyCodec.parsePublicKey(MERCHANT_PUB, RSA);
            PrivateKey platformPriv = KeyCodec.parsePrivateKey(PLATFORM_PRIV, RSA);
            byte[] badKey = Arrays.copyOf(dek, 31);
            String payload = DekPayload.encode(new DekPayload("AES-256-GCM", badKey, iv));
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("x-wop-timestamp", "1758900000000");
            headers.put("x-wop-nonce", "faultnonce00000000000000000002");
            headers.put("x-wop-encrypt", EncryptHeader.buildL2(Codec.b64UrlEncode(
                    RSA.keyEncrypt().encrypt(Codec.utf8(payload), merchantPub))));
            headers.put("x-wop-content-digest", ContentDigest.build(RSA, wire));
            List<String> signed = new ArrayList<>(List.of("x-wop-content-digest", "x-wop-encrypt",
                    "x-wop-nonce", "x-wop-timestamp"));
            Map<String, String> sub = new TreeMap<>();
            signed.forEach(n -> sub.put(n, headers.get(n)));
            String canonical = CanonicalRequest.build("v1/1800", "POST", "/p", "",
                    CanonicalRequest.canonicalHeaders(sub));
            headers.put("x-wop-sign", SignHeader.build("WOP-RSA3072-SHA256", 1800, signed,
                    Codec.b64UrlEncode(RSA.signature().sign(Codec.utf8(canonical), platformPriv,
                            Codec.utf8("1234567812345678")))));

            assertEquals(VerifyResult.Reason.DECRYPT_FAILED,
                    client.verifyResponse(headers, wire, "/p").reason());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void crossSuiteDeclaredInResponseFailsExplicitly() {
        // 故障：对端声明 SM2 套件但本客户端配置为 RSA——声明与配置均为公开结构知识，
        // 协议类明确拒绝（interop 合同 n11），不进入密钥参与的模糊验签
        byte[] body = Codec.utf8("{}");
        Map<String, String> headers = platformResponse("/p", body, false, null);
        wireOf(headers);
        SignHeader.Parsed parsed = SignHeader.parse(headers.get("x-wop-sign"));
        headers.put("x-wop-sign", SignHeader.build("WOP-SM2-SM3", 1800, parsed.signedHeaders(),
                parsed.signature()));
        VerifyResult result = client.verifyResponse(headers, body, "/p");
        assertEquals(VerifyResult.Reason.SUITE_MISMATCH, result.reason());
        assertTrue(result.message().contains("不符"));
    }

    @Test
    void pathReplayAcrossEndpointsFails() {
        // 故障：签名覆盖 /gateway/pay，攻击者把同一响应重放到 /gateway/refund——URI 入签防跨端点重放
        byte[] body = Codec.utf8("{\"ok\":true}");
        Map<String, String> headers = platformResponse("/gateway/pay", body, false, null);
        wireOf(headers);
        assertEquals(VerifyResult.Reason.SIGNATURE_FAILED,
                client.verifyResponse(headers, body, "/gateway/refund").reason());
        // 原路径仍然通过（自证不是签名构造错误）
        assertTrue(client.verifyResponse(headers, body, "/gateway/pay").ok());
    }

    @Test
    void urlEncodedSignaturePollutionFailsExplicitly() {
        // P6 拉齐（interop n06 裁决）：签名段携带 '=' 等 b64url 非法字符属公开结构知识，
        // 协议类明确拒绝（格式类错误码），非验签模糊
        byte[] body = Codec.utf8("{}");
        Map<String, String> headers = platformResponse("/p", body, false, null);
        wireOf(headers);
        SignHeader.Parsed parsed = SignHeader.parse(headers.get("x-wop-sign"));
        headers.put("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/" + String.join(";", parsed.signedHeaders())
                + "/" + parsed.signature().substring(0, 40) + "%3D");
        VerifyResult result = client.verifyResponse(headers, body, "/p");
        assertEquals(VerifyResult.Reason.INVALID_SIGN_HEADER, result.reason());
        assertTrue(result.message().contains("非法字符"));
    }


    @Test
    void mixedCaseInboundHeaderNamesTolerated() {
        // 故障形态：非官方适配器送来大小写混合头名——core 层大小写不敏感兜底
        byte[] body = Codec.utf8("{}");
        Map<String, String> headers = platformResponse("/p", body, false, null);
        wireOf(headers);
        Map<String, String> mixed = new LinkedHashMap<>();
        headers.forEach((k, v) -> mixed.put(k.equals("x-wop-sign") ? "X-WOP-SIGN" : k.toUpperCase(java.util.Locale.ROOT), v));
        assertTrue(client.verifyResponse(mixed, body, "/p").ok());
    }
}
