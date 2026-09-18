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
import com.wanlianyida.wop.config.ConfigUrlUtils;
import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.config.WopRequestContext;
import com.wanlianyida.wop.config.WopSdkConfig;
import com.wanlianyida.wop.config.WopSdkConfigLoader;
import com.wanlianyida.wop.crypto.strategies.CipherResult;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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

    /** 平台响应签名 userId（协议固定值，与 Go 参考实现 sm2PlatformUserID 一致；仅入向验签使用，
     *  非出向默认回退——出向恒为 x-wop-appkey 头值，D14）。 */
    private static final byte[] PLATFORM_SIGN_USER_ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);

    /** 默认客户端缓存（K15/K26）。 */
    private static volatile WopClient defaultClientInstance;
    private static final Object DEFAULT_CLIENT_LOCK = new Object();

    private final Config config;
    private final WopSdkConfig sdkConfig;
    /** §6.4：none() 时复用的预解析默认上下文。 */
    private final WopRequestContext defaultRequestContext;
    private final Transport transport;
    private final AlgorithmSuite suite;
    private final PrivateKey merchantPrivateKey;
    private final PublicKey platformPublicKey;
    private final LongSupplier clock;
    private final Supplier<String> nonceGen;
    private final SecureRandom random;

    /** 测试便捷构造（随机源退默认 CSPRNG）。 */
    WopClient(Config config, LongSupplier clock, Supplier<String> nonceGen) {
        this(config, null, null, clock, nonceGen, new SecureRandom());
    }

    /** 全量确定性钩子（interop 联调合同）：时钟/nonce/随机源可注入；生产走 Builder 默认 CSPRNG。 */
    WopClient(Config config, LongSupplier clock, Supplier<String> nonceGen, SecureRandom random) {
        this(config, null, null, clock, nonceGen, random);
    }

    private WopClient(Config config, WopSdkConfig sdkConfig, Transport transport,
                      LongSupplier clock, Supplier<String> nonceGen, SecureRandom random) {
        this.config = config;
        this.sdkConfig = sdkConfig;
        this.defaultRequestContext = sdkConfig == null
                ? null
                : WopRequestContext.resolve(sdkConfig, WopRequestOptions.none());
        this.transport = transport;
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

    /** 惰性：loadDefault → 传输发现 → 构造；缓存复用（K15）。 */
    public static WopClient defaultClient() {
        WopClient local = defaultClientInstance;
        if (local != null) {
            return local;
        }
        synchronized (DEFAULT_CLIENT_LOCK) {
            if (defaultClientInstance == null) {
                defaultClientInstance = fromConfig(WopSdkConfigLoader.loadDefault());
            }
            return defaultClientInstance;
        }
    }

    /** 显式配置构造（不进默认实例缓存，K11）。 */
    public static WopClient fromConfig(WopSdkConfig config) {
        Objects.requireNonNull(config, "config");
        Transport resolvedTransport = config.transport();
        if (resolvedTransport == null) {
            resolvedTransport = TransportFactory.discover().create(config.serverRoot());
        }
        Config clientConfig = new Config(
                config.appKey(),
                AlgorithmSuite.parse(config.suite()),
                config.merchantPrivateKey(),
                config.platformPublicKey(),
                config.expiredSeconds());
        return new WopClient(clientConfig, config, resolvedTransport,
                System::currentTimeMillis, defaultNonceSupplier(), new SecureRandom());
    }

    /** 丢弃默认实例与初始化状态（轮换须先 {@link WopSdkConfigLoader#clearCache()}，K26）。 */
    public static void resetDefault() {
        synchronized (DEFAULT_CLIENT_LOCK) {
            defaultClientInstance = null;
        }
    }

    /**
     * 一站式：签名 → 发送 → 非 2xx 拦截 → 验签解密（§2 execute 语义）。
     */
    public VerifyResult execute(String method, String path, byte[] body, SecurityLevel level) {
        return execute(method, path, body, level, WopRequestOptions.none());
    }

    /**
     * 带请求级覆盖的一站式入口（§6/K24）：合并后出/入向凭证与 Failover 候选同源。
     */
    public VerifyResult execute(String method, String path, byte[] body, SecurityLevel level,
                                WopRequestOptions options) {
        if (transport == null) {
            throw WopError.configuration("execute 需要经 fromConfig/defaultClient 构造的客户端");
        }
        ConfigUrlUtils.validateApiPath(path);
        WopRequestContext ctx = resolveContext(options);
        RequestDraft draft = buildRequestInternal(method, path, body, level, ctx.outbound());
        Transport sending = new FailoverTransport(transport, ctx);
        TransportResponse response = sending.send(draft, ctx.toTransportCall());
        return finishExecute(response, draft, ctx.inbound());
    }

    private VerifyResult finishExecute(TransportResponse response, RequestDraft draft,
                                         WopRequestContext.Inbound inbound) {
        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            throw new WopGatewayResponseException(status, response.body());
        }
        return verifyInbound(response.headers(), response.body(), draft.path(), inbound);
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
        return buildRequest(method, path, body, level, WopRequestOptions.none());
    }

    /**
     * 带请求级覆盖的出向构造（K24）；未设置字段沿用全局配置。
     */
    public RequestDraft buildRequest(String method, String path, byte[] body, SecurityLevel level,
                                     WopRequestOptions options) {
        if (options == null || options.isEmpty()) {
            return buildRequestInternal(method, path, body, level, null);
        }
        if (sdkConfig == null) {
            throw WopError.configuration("请求级覆盖需要经 fromConfig/defaultClient 构造的客户端");
        }
        return buildRequestInternal(method, path, body, level, resolveContext(options).outbound());
    }

    private RequestDraft buildRequestInternal(String method, String path, byte[] body, SecurityLevel level,
                                              WopRequestContext.Outbound outbound) {
        if (method == null || method.trim().isEmpty()) {
            throw WopError.configuration("HTTP method 为空");
        }
        ConfigUrlUtils.validateApiPath(path);
        if (level == null) {
            throw WopError.configuration("SecurityLevel 为空（L0|L2）");
        }
        String upperMethod = method.trim().toUpperCase(java.util.Locale.ROOT);
        boolean hasBody = body != null && body.length > 0;
        if (level == SecurityLevel.L2 && !hasBody) {
            throw WopError.configuration("L2 加密需要非空 body");
        }

        AlgorithmSuite effectiveSuite = outbound != null ? outbound.suite() : suite;
        PrivateKey effectiveMerchantKey = outbound != null ? outbound.merchantPrivateKey() : merchantPrivateKey;
        PublicKey effectivePlatformKey = outbound != null ? outbound.platformPublicKey() : platformPublicKey;
        String effectiveAppKey = outbound != null ? outbound.appKey() : config.appKey();
        long effectiveExpired = outbound != null ? outbound.expiredSeconds() : config.expiredSeconds();

        byte[] wireBody = body;
        if (!hasBody) {
            wireBody = null;   // 无 body 统一为 null（空数组归一，D2）
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HEADER_APPKEY, effectiveAppKey);
        headers.put(HEADER_TIMESTAMP, Long.toString(clock.getAsLong()));
        headers.put(HEADER_NONCE, nonceGen.get());

        if (level == SecurityLevel.L2) {
            byte[] dekKey = new byte[effectiveSuite.messageEncrypt().keyLength()];
            random.nextBytes(dekKey);
            CipherResult result = effectiveSuite.messageEncrypt().encrypt(body, dekKey, random);
            wireBody = EncryptedEnvelope.wrap(Codec.b64UrlEncode(result.cipher()));
            String dekPayload = DekPayload.encode(
                    new DekPayload(effectiveSuite.expectedDekAlg(), dekKey, result.iv()));
            byte[] wrapped = effectiveSuite.keyEncrypt().encrypt(Codec.utf8(dekPayload),
                    effectivePlatformKey, random);
            headers.put(HEADER_ENCRYPT, EncryptHeader.buildL2(Codec.b64UrlEncode(wrapped)));
        }

        if (wireBody != null) {
            headers.put(HEADER_DIGEST, ContentDigest.build(effectiveSuite, wireBody));
        }

        java.util.SortedSet<String> signedNames = new java.util.TreeSet<>();
        for (String name : headers.keySet()) {
            signedNames.add(name);
        }
        List<String> signedHeaders = Collections.unmodifiableList(new ArrayList<>(signedNames));
        String authString = SignHeader.PROTOCOL_VERSION + "/" + effectiveExpired;
        String canonical = CanonicalRequest.build(authString, upperMethod, path, "",
                CanonicalRequest.canonicalHeaders(subMap(headers, signedHeaders)));
        byte[] signature = effectiveSuite.signature().sign(Codec.utf8(canonical), effectiveMerchantKey,
                Codec.utf8(effectiveAppKey));
        headers.put(HEADER_SIGN, SignHeader.build(effectiveSuite.securityReq(), effectiveExpired,
                signedHeaders, Codec.b64UrlEncode(signature)));

        return new RequestDraft(upperMethod, path, headers, wireBody);
    }

    // ==================== 入向（F6：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密） ====================

    /** 校验网关响应（canonical URI = 原请求路径；无路径无法重建 canonical，必须显式提供）。 */
    public VerifyResult verifyResponse(Map<String, String> headers, byte[] body, String requestPath) {
        return verifyResponse(headers, body, requestPath, WopRequestOptions.none());
    }

    /**
     * 带请求级覆盖的响应验签（K24）；仅消费入向凭证字段。
     */
    public VerifyResult verifyResponse(Map<String, String> headers, byte[] body, String requestPath,
                                       WopRequestOptions options) {
        if (options == null || options.isEmpty()) {
            return verifyInbound(headers, body, requestPath, null);
        }
        if (sdkConfig == null) {
            throw WopError.configuration("凭证覆盖需要经 fromConfig 构造的客户端");
        }
        return verifyInbound(headers, body, requestPath,
                WopRequestContext.resolveInboundOnly(sdkConfig, options).inbound());
    }

    /** 校验 SDK 发送流程的响应（路径取自草稿）。 */
    public VerifyResult verifyResponse(TransportResponse response, RequestDraft draft) {
        return verifyResponse(response, draft, WopRequestOptions.none());
    }

    /** 带请求级覆盖的响应验签（路径取自草稿）。 */
    public VerifyResult verifyResponse(TransportResponse response, RequestDraft draft,
                                       WopRequestOptions options) {
        return verifyResponse(response.headers(), response.body(), draft.path(), options);
    }

    /** 校验平台回调（canonical URI = 回调 path）。 */
    public VerifyResult verifyCallback(Map<String, String> headers, byte[] body, String callbackPath) {
        return verifyCallback(headers, body, callbackPath, WopRequestOptions.none());
    }

    /**
     * 平台回调验签 + 凭证覆盖（K10）：仅消费 options 中凭证字段，超时/域名字段忽略。
     */
    public VerifyResult verifyCallback(Map<String, String> headers, byte[] body, String callbackPath,
                                       WopRequestOptions options) {
        if (options == null || options.isEmpty()) {
            return verifyInbound(headers, body, callbackPath, null);
        }
        if (sdkConfig == null) {
            throw WopError.configuration("verifyCallback 凭证覆盖需要经 fromConfig 构造的客户端");
        }
        return verifyInbound(headers, body, callbackPath,
                WopRequestContext.resolveInboundOnly(sdkConfig, options).inbound());
    }

    private WopRequestContext resolveContext(WopRequestOptions options) {
        if (options == null || options.isEmpty()) {
            return defaultRequestContext;
        }
        return WopRequestContext.resolve(sdkConfig, options);
    }

    /** 入向统一实现（F6 固定顺序：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密）；永不抛异常。 */
    private VerifyResult verifyInbound(Map<String, String> headers, byte[] body, String path,
                                       WopRequestContext.Inbound inbound) {
        AlgorithmSuite clientSuite = inbound != null ? inbound.suite() : suite;
        PublicKey verifyKey = inbound != null ? inbound.platformPublicKey() : platformPublicKey;
        PrivateKey decryptKey = inbound != null ? inbound.merchantPrivateKey() : merchantPrivateKey;

        Map<String, String> lower = lowerCase(headers);

        // 1. 签名头存在性与格式（解析类，明确）
        String signHeader = lower.get(HEADER_SIGN);
        if (signHeader == null || signHeader.trim().isEmpty()) {
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
        if (!inboundSuite.securityReq().equals(clientSuite.securityReq())) {
            return VerifyResult.fail(VerifyResult.Reason.SUITE_MISMATCH,
                    "响应声明 " + inboundSuite.securityReq() + " 与客户端配置 "
                            + clientSuite.securityReq() + " 不符");
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
        if (hasBody && (lower.get(HEADER_DIGEST) == null || lower.get(HEADER_DIGEST).trim().isEmpty())) {
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
            // D14：入向验签 userId = 平台协议固定值（与 Go 参考实现 sm2PlatformUserID 一致，仅入向）
            verified = inboundSuite.signature().verify(Codec.utf8(canonical), signature,
                    verifyKey, PLATFORM_SIGN_USER_ID);
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
            dekPlain = inboundSuite.keyEncrypt().decrypt(Codec.b64UrlDecode(encrypt.dek()), decryptKey);
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

    /** 客户端配置（不可变，record 等价值语义：equals/hashCode 按全部字段）。 */
    static final class Config {

        private final String appKey;
        private final AlgorithmSuite suite;
        private final String merchantPrivateKey;
        private final String platformPublicKey;
        private final long expiredSeconds;

        Config(String appKey, AlgorithmSuite suite, String merchantPrivateKey,
               String platformPublicKey, long expiredSeconds) {
            this.appKey = appKey;
            this.suite = suite;
            this.merchantPrivateKey = merchantPrivateKey;
            this.platformPublicKey = platformPublicKey;
            this.expiredSeconds = expiredSeconds;
        }

        String appKey() {
            return appKey;
        }

        AlgorithmSuite suite() {
            return suite;
        }

        String merchantPrivateKey() {
            return merchantPrivateKey;
        }

        String platformPublicKey() {
            return platformPublicKey;
        }

        long expiredSeconds() {
            return expiredSeconds;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Config)) {
                return false;
            }
            Config that = (Config) o;
            return expiredSeconds == that.expiredSeconds
                    && Objects.equals(appKey, that.appKey)
                    && Objects.equals(suite, that.suite)
                    && Objects.equals(merchantPrivateKey, that.merchantPrivateKey)
                    && Objects.equals(platformPublicKey, that.platformPublicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(appKey, suite, merchantPrivateKey, platformPublicKey, expiredSeconds);
        }

        @Override
        public String toString() {
            // K16：凭证字段打码
            return "Config[appKey=" + appKey + ", suite=" + suite
                    + ", merchantPrivateKey=****, platformPublicKey=****"
                    + ", expiredSeconds=" + expiredSeconds + "]";
        }
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
        private String serverRoot;
        private List<String> backupServerRoots = Collections.emptyList();
        private HttpClientSettings httpClient = HttpClientSettings.defaults();
        private Transport transport;

        /** 商户 appKey（x-wop-appkey，必填）。 */
        public Builder appKey(String appKey) {
            this.appKey = appKey;
            return this;
        }

        /** securityReq，如 WOP-RSA2048-SHA256 / WOP-RSA3072-SHA256 / WOP-RSA4096-SHA256 / WOP-SM2-SM3。 */
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

        /** 主网关根地址（HTTPS 绝对 URL，含 context-path；设置后走 {@link #fromConfig} 路径，K11）。 */
        public Builder serverRoot(String serverRoot) {
            this.serverRoot = serverRoot;
            return this;
        }

        /** 备用网关根地址（有序，仅全局）。 */
        public Builder backupServerRoots(String... backupServerRoots) {
            this.backupServerRoots = backupServerRoots == null
                    ? Collections.emptyList() : Arrays.asList(backupServerRoots);
            return this;
        }

        /** HTTP 客户端全局参数。 */
        public Builder httpClient(HttpClientSettings httpClient) {
            this.httpClient = httpClient == null ? HttpClientSettings.defaults() : httpClient;
            return this;
        }

        /** 可选注入传输；缺省时 {@link #fromConfig} 走 SPI 发现。 */
        public Builder transport(Transport transport) {
            this.transport = transport;
            return this;
        }

        /** 构造客户端：必填项与套件 fail-fast 校验，密钥按套件族即时解析（非法抛 {@link WopError}，configuration 类）。 */
        public WopClient build() {
            if (appKey == null || appKey.trim().isEmpty()) {
                throw WopError.configuration("appKey 为空");
            }
            if (suite == null || suite.trim().isEmpty()) {
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
            if (merchantPrivateKey == null || merchantPrivateKey.trim().isEmpty()) {
                throw WopError.configuration("merchantPrivateKey 为空");
            }
            if (platformPublicKey == null || platformPublicKey.trim().isEmpty()) {
                throw WopError.configuration("platformPublicKey 为空");
            }
            if (serverRoot != null && !serverRoot.trim().isEmpty()) {
                WopSdkConfig config = new WopSdkConfig.Builder()
                        .appKey(appKey)
                        .suite(suite)
                        .merchantPrivateKey(merchantPrivateKey)
                        .platformPublicKey(platformPublicKey)
                        .serverRoot(serverRoot)
                        .backupServerRoots(backupServerRoots)
                        .expiredSeconds(expiredSeconds)
                        .httpClient(httpClient)
                        .transport(transport)
                        .build();
                return fromConfig(config);
            }
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
