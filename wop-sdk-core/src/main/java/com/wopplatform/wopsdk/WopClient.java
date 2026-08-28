package com.wopplatform.wopsdk;

import com.wopplatform.wopsdk.crypto.AlgorithmSuite;
import com.wopplatform.wopsdk.crypto.CanonicalRequest;
import com.wopplatform.wopsdk.crypto.Codec;
import com.wopplatform.wopsdk.crypto.ContentDigest;
import com.wopplatform.wopsdk.crypto.DekPayload;
import com.wopplatform.wopsdk.crypto.EncryptedEnvelope;
import com.wopplatform.wopsdk.crypto.EncryptHeader;
import com.wopplatform.wopsdk.crypto.KeyCodec;
import com.wopplatform.wopsdk.crypto.SignHeader;
import com.wopplatform.wopsdk.crypto.WopSuiteException;
import com.wopplatform.wopsdk.crypto.strategies.CipherResult;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * WOP 商户客户端（协议核心门面）：出向 buildRequest（L0/L2 信封）与入向
 * verifyResponse/verifyCallback（F6 固定顺序校验）。
 * <p>
 * 请求方向：商户私钥加签、平台公钥包 DEK；响应/回调方向：平台公钥验签、商户私钥解包。
 * 线程安全（不可变；密钥解析缓存见 KeyCodec）。
 */
public final class WopClient {

    /** 默认签名有效时长（秒，与网关响应侧一致）。 */
    public static final long DEFAULT_EXPIRED_SECONDS = 1800;

    private static final String HEADER_APPKEY = "x-wop-appkey";
    private static final String HEADER_SIGN = "x-wop-sign";
    private static final String HEADER_TIMESTAMP = "x-wop-timestamp";
    private static final String HEADER_NONCE = "x-wop-nonce";
    private static final String HEADER_DIGEST = "x-wop-content-digest";
    private static final String HEADER_ENCRYPT = "x-wop-encrypt";

    private final Config config;
    private final AlgorithmSuite suite;
    private final PrivateKey merchantPrivateKey;
    private final PublicKey platformPublicKey;
    private final LongSupplier clock;
    private final Supplier<String> nonceGen;
    private final SecureRandom random = new SecureRandom();

    WopClient(Config config, LongSupplier clock, Supplier<String> nonceGen) {
        this.config = config;
        this.suite = config.suite();
        this.merchantPrivateKey = KeyCodec.parsePrivateKey(config.merchantPrivateKey(), suite);
        this.platformPublicKey = KeyCodec.parsePublicKey(config.platformPublicKey(), suite);
        this.clock = clock;
        this.nonceGen = nonceGen;
    }

    public static Builder builder() {
        return new Builder();
    }

    // ==================== 出向 ====================

    /**
     * 构造请求草稿（headers + wireBody，零网络 IO）。
     *
     * @param method HTTP 方法（大小写不敏感）
     * @param path   请求路径（以 / 开头）
     * @param body   业务报文字节；null/空 = 无 body（GET 语义，digest 头缺席，D2）
     * @param level  L0 明文 / L2 数字信封（L2 需要非空 body）
     */
    public RequestDraft buildRequest(String method, String path, byte[] body, SecurityLevel level) {
        if (method == null || method.isBlank()) {
            throw new WopSdkException("HTTP method 为空");
        }
        if (path == null || path.isBlank()) {
            throw new WopSdkException("请求路径为空");
        }
        if (level == null) {
            throw new WopSdkException("SecurityLevel 为空（L0|L2）");
        }
        String upperMethod = method.trim().toUpperCase(java.util.Locale.ROOT);
        boolean hasBody = body != null && body.length > 0;
        if (level == SecurityLevel.L2 && !hasBody) {
            throw new WopSdkException("L2 加密需要非空 body");
        }

        byte[] wireBody = body;
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HEADER_APPKEY, config.appKey());
        headers.put(HEADER_TIMESTAMP, Long.toString(clock.getAsLong()));
        headers.put(HEADER_NONCE, nonceGen.get());

        if (level == SecurityLevel.L2) {
            // F5：DEK key 由 CSPRNG 生成；IV 由策略唯一生成点产出（I4），随密文同源携带
            byte[] dekKey = new byte[suite.messageEncrypt().keyLength()];
            random.nextBytes(dekKey);
            CipherResult result = suite.messageEncrypt().encrypt(body, dekKey);
            wireBody = EncryptedEnvelope.wrap(Codec.b64UrlEncode(result.cipher()));
            String dekPayload = DekPayload.encode(
                    new DekPayload(suite.expectedDekAlg(), dekKey, result.iv()));
            byte[] wrapped = suite.keyEncrypt().encrypt(Codec.utf8(dekPayload), platformPublicKey);
            headers.put(HEADER_ENCRYPT, EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
        }

        if (wireBody != null && wireBody.length > 0) {
            headers.put(HEADER_DIGEST, ContentDigest.build(suite, wireBody));
        }

        // signedHeaders = 参与签名的头按名称 ASCII 升序（appkey 基础 + 有 body 必含 digest（I1）
        // + 加密必含 x-wop-encrypt + nonce/timestamp）
        java.util.SortedSet<String> signedNames = new java.util.TreeSet<>();
        for (String name : headers.keySet()) {
            if (name.equals(HEADER_TIMESTAMP) || name.equals(HEADER_NONCE)
                    || name.equals(HEADER_APPKEY) || name.equals(HEADER_DIGEST)
                    || name.equals(HEADER_ENCRYPT)) {
                signedNames.add(name);
            }
        }
        List<String> signedHeaders = List.copyOf(signedNames);
        String authString = SignHeader.PROTOCOL_VERSION + "/" + config.expiredSeconds();
        String canonical = CanonicalRequest.build(authString, upperMethod, path, "",
                CanonicalRequest.canonicalHeaders(subMap(headers, signedHeaders)));
        byte[] signature = suite.signature().sign(Codec.utf8(canonical), merchantPrivateKey);
        headers.put(HEADER_SIGN, SignHeader.build(suite.securityReq(), config.expiredSeconds(),
                signedHeaders, Codec.b64UrlEncode(signature)));

        return new RequestDraft(upperMethod, path, headers, wireBody);
    }

    // ==================== 入向（F6：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密） ====================

    /** 校验网关响应（canonical URI = 原请求路径；无路径无法重建 canonical，必须显式提供）。 */
    public VerifyResult verifyResponse(Map<String, String> headers, byte[] body, String requestPath) {
        return verifyInbound(headers, body, requestPath);
    }

    /** 校验 SDK 发送流程的响应（路径取自草稿）。 */
    public VerifyResult verifyResponse(TransportResponse response, RequestDraft draft) {
        return verifyInbound(response.headers(), response.body(), draft.path());
    }

    /** 校验平台回调（canonical URI = 回调 path）。 */
    public VerifyResult verifyCallback(Map<String, String> headers, byte[] body, String callbackPath) {
        return verifyInbound(headers, body, callbackPath);
    }

    private VerifyResult verifyInbound(Map<String, String> headers, byte[] body, String path) {
        Map<String, String> lower = lowerCase(headers);

        // 1. 签名头存在性与格式（解析类，明确）
        String signHeader = lower.get(HEADER_SIGN);
        if (signHeader == null || signHeader.isBlank()) {
            return VerifyResult.fail(VerifyResult.Reason.MISSING_SIGN_HEADER, null);
        }
        SignHeader.Parsed sign;
        try {
            sign = SignHeader.parse(signHeader);
        } catch (WopSdkException e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_SIGN_HEADER, e.getMessage());
        }

        // 2. 套件（支持类，明确）
        AlgorithmSuite inboundSuite;
        try {
            inboundSuite = AlgorithmSuite.parse(sign.securityReq());
        } catch (WopSuiteException e) {
            return VerifyResult.fail(VerifyResult.Reason.UNSUPPORTED_SUITE, e.getMessage());
        }

        // 3. 加密指令（解析类，明确；头缺席 = L0）
        EncryptHeader.Parsed encrypt;
        try {
            encrypt = EncryptHeader.parse(lower.get(HEADER_ENCRYPT));
        } catch (WopSdkException e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_ENCRYPT_HEADER, e.getMessage());
        }

        // 4. signedHeaders 完整性（I1/D2：有 body 必含 digest；L2 必含 x-wop-encrypt）
        boolean hasBody = body != null && body.length > 0;
        if (hasBody && !sign.signedHeaders().contains(HEADER_DIGEST)) {
            return VerifyResult.fail(VerifyResult.Reason.MISSING_SIGNED_HEADER,
                    "有 body 时 signedHeaders 必含 " + HEADER_DIGEST + "（I1）");
        }
        if (encrypt.isEncrypted() && !sign.signedHeaders().contains(HEADER_ENCRYPT)) {
            return VerifyResult.fail(VerifyResult.Reason.MISSING_SIGNED_HEADER,
                    "L2 加密时 signedHeaders 必含 " + HEADER_ENCRYPT);
        }

        // 5. 重建 canonical（声明的头缺失 → 明确拒绝）
        Map<String, String> signed = new TreeMap<>();
        for (String name : sign.signedHeaders()) {
            String value = lower.get(name);
            if (value == null) {
                return VerifyResult.fail(VerifyResult.Reason.MISSING_HEADER, name);
            }
            signed.put(name, value);
        }
        String canonical = CanonicalRequest.build(
                sign.protocolVersion() + "/" + sign.expiredSeconds(), "POST", path, "",
                CanonicalRequest.canonicalHeaders(signed));

        // 6. 验签（先验签后解密，I2；失败对外模糊，I7）
        boolean verified;
        try {
            byte[] signature = Codec.b64UrlDecode(sign.signature());
            verified = inboundSuite.signature().verify(Codec.utf8(canonical), signature, platformPublicKey);
        } catch (RuntimeException e) {
            verified = false;
        }
        if (!verified) {
            return VerifyResult.fail(VerifyResult.Reason.SIGNATURE_FAILED, null);
        }

        // 7. digest 复核（完整性类，明确；对象 = 线上原始报文字节）
        if (hasBody) {
            String digestHeader = lower.get(HEADER_DIGEST);
            if (digestHeader == null || digestHeader.isBlank()) {
                return VerifyResult.fail(VerifyResult.Reason.MISSING_DIGEST_HEADER, null);
            }
            ContentDigest.Parsed digest;
            try {
                digest = ContentDigest.parse(digestHeader, inboundSuite);
            } catch (WopSdkException e) {
                return VerifyResult.fail(VerifyResult.Reason.INVALID_DIGEST_HEADER, e.getMessage());
            }
            if (!Codec.hexLower(inboundSuite.digest().digest(body)).equals(digest.hex())) {
                return VerifyResult.fail(VerifyResult.Reason.DIGEST_MISMATCH, null);
            }
        } else if (lower.containsKey(HEADER_DIGEST)) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_DIGEST_HEADER, "无 body 时 digest 头必须缺席（D2）");
        }

        // 8. L2：DEK 解包（模糊）→ alg 族比对（明确，bulk 解密前，D8）→ bulk 解密（模糊）
        if (!encrypt.isEncrypted()) {
            return VerifyResult.ok(body);
        }
        byte[] dekPlain;
        try {
            dekPlain = inboundSuite.keyEncrypt().decrypt(Codec.b64UrlDecode(encrypt.dek()), merchantPrivateKey);
        } catch (RuntimeException e) {
            return VerifyResult.fail(VerifyResult.Reason.DECRYPT_FAILED, null);
        }
        DekPayload dek;
        try {
            dek = DekPayload.decode(new String(dekPlain, StandardCharsets.UTF_8));
        } catch (WopSdkException e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_ENCRYPT_HEADER, "dek 载荷格式非法: " + e.getMessage());
        }
        if (!dek.alg().equals(inboundSuite.expectedDekAlg())) {
            return VerifyResult.fail(VerifyResult.Reason.DEK_ALG_MISMATCH,
                    dek.alg() + "（期望 " + inboundSuite.expectedDekAlg() + "）");
        }
        byte[] cipher;
        try {
            cipher = EncryptedEnvelope.cipherOf(body);
        } catch (WopSdkException e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_ENCRYPTED_BODY, e.getMessage());
        }
        byte[] plain;
        try {
            plain = inboundSuite.messageEncrypt().decrypt(cipher, dek.iv(), dek.key());
        } catch (RuntimeException e) {
            return VerifyResult.fail(VerifyResult.Reason.DECRYPT_FAILED, null);
        }
        return VerifyResult.ok(plain);
    }

    // ==================== 配置 ====================

    record Config(String appKey, AlgorithmSuite suite, String merchantPrivateKey,
                  String platformPublicKey, long expiredSeconds) {
    }

    private static Map<String, String> subMap(Map<String, String> headers, List<String> names) {
        Map<String, String> sub = new LinkedHashMap<>();
        for (String name : names) {
            sub.put(name, headers.get(name));
        }
        return sub;
    }

    private static Map<String, String> lowerCase(Map<String, String> headers) {
        Map<String, String> lower = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            lower.putAll(headers);
        }
        return lower;
    }

    /** Builder（链式；build() fail-fast 校验全部必填与密钥合法性）。 */
    public static final class Builder {

        private String appKey;
        private String suite;
        private String merchantPrivateKey;
        private String platformPublicKey;
        private long expiredSeconds = DEFAULT_EXPIRED_SECONDS;

        public Builder appKey(String appKey) {
            this.appKey = appKey;
            return this;
        }

        /** securityReq，如 WOP-RSA3072-SHA256 / WOP-RSA4096-SHA256 / WOP-SM2-SM3。 */
        public Builder suite(String securityReq) {
            this.suite = securityReq;
            return this;
        }

        public Builder merchantPrivateKey(String pemOrBase64) {
            this.merchantPrivateKey = pemOrBase64;
            return this;
        }

        public Builder platformPublicKey(String pemOrBase64) {
            this.platformPublicKey = pemOrBase64;
            return this;
        }

        public Builder expiredSeconds(long seconds) {
            this.expiredSeconds = seconds;
            return this;
        }

        public WopClient build() {
            if (appKey == null || appKey.isBlank()) {
                throw new WopSdkException("appKey 为空");
            }
            if (suite == null || suite.isBlank()) {
                throw new WopSdkException("suite（securityReq）为空");
            }
            if (expiredSeconds <= 0) {
                throw new WopSdkException("expiredSeconds 须为正整数");
            }
            AlgorithmSuite parsed;
            try {
                parsed = AlgorithmSuite.parse(suite);
            } catch (WopSuiteException e) {
                throw new WopSdkException(e.getMessage(), e);
            }
            if (merchantPrivateKey == null || merchantPrivateKey.isBlank()) {
                throw new WopSdkException("merchantPrivateKey 为空");
            }
            if (platformPublicKey == null || platformPublicKey.isBlank()) {
                throw new WopSdkException("platformPublicKey 为空");
            }
            // fail-fast：密钥按套件族解析（D12 格式、长度一致性在 KeyCodec 内校验）
            return new WopClient(new Config(appKey, parsed, merchantPrivateKey, platformPublicKey, expiredSeconds),
                    System::currentTimeMillis, defaultNonceSupplier());
        }
    }

    private static Supplier<String> defaultNonceSupplier() {
        SecureRandom random = new SecureRandom();
        return () -> {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            return Codec.hexLower(bytes);
        };
    }
}
