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
import com.wanlianyida.wop.crypto.WopSuiteException;
import com.wanlianyida.wop.crypto.strategies.CipherResult;
import com.wanlianyida.wop.crypto.strategies.Sm2Support;

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
    private final SecureRandom random;

    /** 测试便捷构造（随机源退默认 CSPRNG）。 */
    WopClient(Config config, LongSupplier clock, Supplier<String> nonceGen) {
        this(config, clock, nonceGen, new SecureRandom());
    }

    /** 全量确定性钩子（interop 联调合同）：时钟/nonce/随机源可注入；生产走 Builder 默认 CSPRNG。 */
    WopClient(Config config, LongSupplier clock, Supplier<String> nonceGen, SecureRandom random) {
        this.config = config;
        this.suite = config.suite();
        this.merchantPrivateKey = KeyCodec.parsePrivateKey(config.merchantPrivateKey(), suite);
        this.platformPublicKey = KeyCodec.parsePublicKey(config.platformPublicKey(), suite);
        this.clock = clock;
        this.nonceGen = nonceGen;
        this.random = random;
    }

    /** 创建 {@link Builder}。 */
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
            throw WopError.configuration("HTTP method 为空");
        }
        if (path == null || path.isBlank()) {
            throw WopError.configuration("请求路径为空");
        }
        if (level == null) {
            throw WopError.configuration("SecurityLevel 为空（L0|L2）");
        }
        String upperMethod = method.trim().toUpperCase(java.util.Locale.ROOT);
        boolean hasBody = body != null && body.length > 0;
        if (level == SecurityLevel.L2 && !hasBody) {
            throw WopError.configuration("L2 加密需要非空 body");
        }

        byte[] wireBody = body;
        if (!hasBody) {
            wireBody = null;   // 无 body 统一为 null（空数组归一，D2）
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HEADER_APPKEY, config.appKey());
        headers.put(HEADER_TIMESTAMP, Long.toString(clock.getAsLong()));
        headers.put(HEADER_NONCE, nonceGen.get());

        if (level == SecurityLevel.L2) {
            // F5：DEK key 由 CSPRNG 生成；IV 由策略唯一生成点产出（I4），随密文同源携带。
            // 随机流消费顺序（interop 合同）：[CEK][IV][wrap 填充随机（OAEP seed/SM2 k）]
            byte[] dekKey = new byte[suite.messageEncrypt().keyLength()];
            random.nextBytes(dekKey);
            CipherResult result = suite.messageEncrypt().encrypt(body, dekKey, random);
            wireBody = EncryptedEnvelope.wrap(Codec.b64UrlEncode(result.cipher()));
            String dekPayload = DekPayload.encode(
                    new DekPayload(suite.expectedDekAlg(), dekKey, result.iv()));
            byte[] wrapped = suite.keyEncrypt().encrypt(Codec.utf8(dekPayload), platformPublicKey, random);
            headers.put(HEADER_ENCRYPT, EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
        }

        if (wireBody != null) {
            // 不变量：hasBody=false 时 wireBody 已归一为 null，非 null 即非空（D2）
            headers.put(HEADER_DIGEST, ContentDigest.build(suite, wireBody));
        }

        // signedHeaders = 参与签名的头按名称 ASCII 升序（appkey 基础 + 有 body 必含 digest（I1）
        // + 加密必含 x-wop-encrypt + nonce/timestamp）
        java.util.SortedSet<String> signedNames = new java.util.TreeSet<>();
        for (String name : headers.keySet()) {
            // headers 白名单恒为签名头（appkey/timestamp/nonce[/digest][/encrypt]），全部参与签名
            signedNames.add(name);
        }
        List<String> signedHeaders = List.copyOf(signedNames);
        String authString = SignHeader.PROTOCOL_VERSION + "/" + config.expiredSeconds();
        String canonical = CanonicalRequest.build(authString, upperMethod, path, "",
                CanonicalRequest.canonicalHeaders(subMap(headers, signedHeaders)));
        // D14：SM2 出向签名 userId = 请求身份（x-wop-appkey）；RSA 忽略
        byte[] signature = suite.signature().sign(Codec.utf8(canonical), merchantPrivateKey,
                Codec.utf8(config.appKey()));
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

    /** 入向统一实现（F6 固定顺序：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密）；永不抛异常。 */
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
        } catch (WopError e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_SIGN_HEADER, e.getMessage());
        }

        // 2. 套件（支持类，明确）+ 响应/配置一致性（公开结构知识，明确——interop n11）
        AlgorithmSuite inboundSuite;
        try {
            inboundSuite = AlgorithmSuite.parse(sign.securityReq());
        } catch (WopSuiteException e) {
            return VerifyResult.fail(VerifyResult.Reason.UNSUPPORTED_SUITE, e.getMessage());
        }
        if (!inboundSuite.securityReq().equals(suite.securityReq())) {
            return VerifyResult.fail(VerifyResult.Reason.SUITE_MISMATCH,
                    "响应声明 " + inboundSuite.securityReq() + " 与客户端配置 " + suite.securityReq() + " 不符");
        }

        // 3. 加密指令（解析类，明确；头缺席 = L0）
        EncryptHeader.Parsed encrypt;
        try {
            encrypt = EncryptHeader.parse(lower.get(HEADER_ENCRYPT));
        } catch (WopError e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_ENCRYPT_HEADER, e.getMessage());
        }

        // 4. D2/I1 前置：有 body → digest 头必在且必入签；L2 → x-wop-encrypt 必入签
        boolean hasBody = body != null && body.length > 0;
        if (hasBody && (lower.get(HEADER_DIGEST) == null || lower.get(HEADER_DIGEST).isBlank())) {
            return VerifyResult.fail(VerifyResult.Reason.MISSING_DIGEST_HEADER, null);
        }
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

        // 6. 验签（先验签后解密，I2；失败对外模糊，I7）。
        //    前置结构校验（公开协议知识，明确——interop n06/n07/n08）：签名段严格 b64url + 套件定长，
        //    与密钥参与的验签失败（模糊）分离。
        byte[] signature;
        try {
            signature = Codec.b64UrlDecode(sign.signature());
        } catch (RuntimeException e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_SIGN_HEADER, e.getMessage());
        }
        if (signature.length != inboundSuite.signatureLength()) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_SIGN_HEADER,
                    "签名长度 " + signature.length + " 字节与套件 " + inboundSuite.securityReq()
                            + " 定长 " + inboundSuite.signatureLength() + " 字节不符");
        }
        boolean verified = false;
        try {
            // D14：入向验签 userId = 平台侧协议默认（与黄金向量/Go 参考一致）
            verified = inboundSuite.signature().verify(Codec.utf8(canonical), signature,
                    platformPublicKey, Sm2Support.DEFAULT_USER_ID);
        } catch (RuntimeException e) {
            verified = false;
        }
        if (!verified) {
            return VerifyResult.fail(VerifyResult.Reason.SIGNATURE_FAILED, null);
        }

        // 7. digest 复核（完整性类，明确；对象 = 线上原始报文字节）
        if (hasBody) {
            ContentDigest.Parsed digest;
            try {
                digest = ContentDigest.parse(lower.get(HEADER_DIGEST), inboundSuite);
            } catch (WopError e) {
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
        } catch (WopError e) {
            return VerifyResult.fail(VerifyResult.Reason.INVALID_ENCRYPT_HEADER, "dek 载荷格式非法: " + e.getMessage());
        }
        if (!dek.alg().equals(inboundSuite.expectedDekAlg())) {
            return VerifyResult.fail(VerifyResult.Reason.DEK_ALG_MISMATCH,
                    dek.alg() + "（期望 " + inboundSuite.expectedDekAlg() + "）");
        }
        byte[] cipher;
        try {
            cipher = EncryptedEnvelope.cipherOf(body);
        } catch (WopError e) {
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

    /** 按签名头清单取子集（保持清单顺序，供 canonicalHeaders 编码）。 */
    private static Map<String, String> subMap(Map<String, String> headers, List<String> names) {
        Map<String, String> sub = new LinkedHashMap<>();
        for (String name : names) {
            sub.put(name, headers.get(name));
        }
        return sub;
    }

    /** 头名大小写不敏感视图（null 安全）。 */
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

        /** 商户 appKey（x-wop-appkey，必填）。 */
        public Builder appKey(String appKey) {
            this.appKey = appKey;
            return this;
        }

        /** securityReq，如 WOP-RSA3072-SHA256 / WOP-RSA4096-SHA256 / WOP-SM2-SM3。 */
        public Builder suite(String securityReq) {
            this.suite = securityReq;
            return this;
        }

        /** 商户私钥（PEM 或 Base64 单行；出向加签/入向解包用，必填）。 */
        public Builder merchantPrivateKey(String pemOrBase64) {
            this.merchantPrivateKey = pemOrBase64;
            return this;
        }

        /** 平台公钥（PEM 或 Base64 单行；DEK 包装/入向验签用，必填）。 */
        public Builder platformPublicKey(String pemOrBase64) {
            this.platformPublicKey = pemOrBase64;
            return this;
        }

        /** 签名有效时长秒数（默认 {@link #DEFAULT_EXPIRED_SECONDS}，须正整数）。 */
        public Builder expiredSeconds(long seconds) {
            this.expiredSeconds = seconds;
            return this;
        }

        /** 构造客户端：必填项与套件 fail-fast 校验，密钥按套件族即时解析（非法抛 {@link WopError}，configuration 类）。 */
        public WopClient build() {
            if (appKey == null || appKey.isBlank()) {
                throw WopError.configuration("appKey 为空");
            }
            if (suite == null || suite.isBlank()) {
                throw WopError.configuration("suite（securityReq）为空");
            }
            if (expiredSeconds <= 0) {
                throw WopError.configuration("expiredSeconds 须为正整数");
            }
            AlgorithmSuite parsed;
            try {
                parsed = AlgorithmSuite.parse(suite);
            } catch (WopSuiteException e) {
                throw WopError.configuration(e.getMessage(), e);
            }
            if (merchantPrivateKey == null || merchantPrivateKey.isBlank()) {
                throw WopError.configuration("merchantPrivateKey 为空");
            }
            if (platformPublicKey == null || platformPublicKey.isBlank()) {
                throw WopError.configuration("platformPublicKey 为空");
            }
            // fail-fast：密钥按套件族解析（D12 格式、长度一致性在 KeyCodec 内校验）
            return new WopClient(new Config(appKey, parsed, merchantPrivateKey, platformPublicKey, expiredSeconds),
                    System::currentTimeMillis, defaultNonceSupplier());
        }
    }

    /** 默认 nonce 生成器：CSPRNG 16 字节 → 小写 hex（32 字符）。 */
    private static Supplier<String> defaultNonceSupplier() {
        SecureRandom random = new SecureRandom();
        return () -> {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            return Codec.hexLower(bytes);
        };
    }
}
