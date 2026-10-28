package com.wanlianyida.wop;

import java.util.Objects;

/**
 * 请求级覆盖（§6.1）；未设置字段沿用全局 JSON 配置。
 */
public final class WopRequestOptions {

    private static final WopRequestOptions NONE = new WopRequestOptions(
            null, null, null, null, 0L, null, 0, 0, null, null);

    private final String appKey;
    private final String suite;
    private final String merchantPrivateKey;
    private final String platformPublicKey;
    private final long expiredSeconds;
    private final String serverRoot;
    private final int connectTimeout;
    private final int readTimeout;
    private final String requestId;
    private final String subMchId;

    private WopRequestOptions(String appKey, String suite, String merchantPrivateKey,
                              String platformPublicKey, long expiredSeconds, String serverRoot,
                              int connectTimeout, int readTimeout, String requestId,
                              String subMchId) {
        this.appKey = appKey;
        this.suite = suite;
        this.merchantPrivateKey = merchantPrivateKey;
        this.platformPublicKey = platformPublicKey;
        this.expiredSeconds = expiredSeconds;
        this.serverRoot = serverRoot;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.requestId = requestId;
        this.subMchId = subMchId;
    }

    /** 无覆盖（复用预解析默认上下文，§6.4）。 */
    public static WopRequestOptions none() {
        return NONE;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String appKey() {
        return appKey;
    }

    public String suite() {
        return suite;
    }

    public String merchantPrivateKey() {
        return merchantPrivateKey;
    }

    public String platformPublicKey() {
        return platformPublicKey;
    }

    /** 0 表示未设置。 */
    public long expiredSeconds() {
        return expiredSeconds;
    }

    public String serverRoot() {
        return serverRoot;
    }

    /** 0 表示未设置。 */
    public int connectTimeout() {
        return connectTimeout;
    }

    /** 0 表示未设置。 */
    public int readTimeout() {
        return readTimeout;
    }

    /** 商户请求标识（透传网关用，不参与签名）。null = 未设置。 */
    public String requestId() {
        return requestId;
    }

    /**
     * 子商户身份（ISV D-13）：出向写入 {@code x-wop-sub-mch-id} 头并参与签名，
     * 值 = 子商户 {@code plf_co_id}。null/空白 = 未设置（应用自身身份，头缺席）。
     */
    public String subMchId() {
        return subMchId;
    }

    /** 是否设置了非空 appKey。 */
    public boolean hasAppKey() {
        return appKey != null && !appKey.trim().isEmpty();
    }

    /** 是否设置了非空 suite。 */
    public boolean hasSuite() {
        return suite != null && !suite.trim().isEmpty();
    }

    /** 是否设置了非空商户私钥。 */
    public boolean hasMerchantPrivateKey() {
        return merchantPrivateKey != null && !merchantPrivateKey.trim().isEmpty();
    }

    /** 是否设置了非空平台公钥。 */
    public boolean hasPlatformPublicKey() {
        return platformPublicKey != null && !platformPublicKey.trim().isEmpty();
    }

    /** 是否设置了正数 expiredSeconds。 */
    public boolean hasExpiredSeconds() {
        return expiredSeconds > 0;
    }

    /** 是否设置了非空 serverRoot。 */
    public boolean hasServerRoot() {
        return serverRoot != null && !serverRoot.trim().isEmpty();
    }

    /** 是否设置了正数 connectTimeout。 */
    public boolean hasConnectTimeout() {
        return connectTimeout > 0;
    }

    /** 是否设置了正数 readTimeout。 */
    public boolean hasReadTimeout() {
        return readTimeout > 0;
    }

    /** 是否设置了非空 requestId。 */
    public boolean hasRequestId() {
        return requestId != null && !requestId.trim().isEmpty();
    }

    /** 是否设置了非空 subMchId。 */
    public boolean hasSubMchId() {
        return subMchId != null && !subMchId.trim().isEmpty();
    }

    /**
     * 解析后 requestId 值：null/空白时返回 null（SDK 缺省生成 UUID，附录 I/I3）；
     * 有值时返回 trim 后的值（控制字符和长度在 build 时已校验）。
     */
    String resolvedRequestId() {
        if (requestId == null) {
            return null;
        }
        String trimmed = requestId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * 解析后 subMchId 值：null/空白时返回 null（头缺席 = 应用自身身份，AC-20 零回归）；
     * 有值时返回 trim 后的值（可打印 ASCII、内部空白与长度在 build 时已校验）。
     */
    String resolvedSubMchId() {
        if (subMchId == null) {
            return null;
        }
        String trimmed = subMchId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * 是否存在请求级配置覆盖（appKey/suite/keys/expiry/serverRoot/timeout）。
     * 仅含 requestId/subMchId 时返回 false——此时 buildRequest 不需要 sdkConfig。
     */
    boolean hasConfigOverrides() {
        return hasAppKey() || hasSuite() || hasMerchantPrivateKey()
                || hasPlatformPublicKey() || hasExpiredSeconds()
                || hasServerRoot() || hasConnectTimeout() || hasReadTimeout();
    }

    /**
     * 是否存在入向验签凭证覆盖（appKey/suite/双钥）。仅含 requestId/subMchId 等出向字段、
     * 或 serverRoot/connectTimeout/readTimeout/expiredSeconds 等传输字段时返回 false——
     * 入向验签直接走默认凭证，不要求 fromConfig 客户端（0.3.0 起有意放宽：此前任何非空
     * options 在无 sdkConfig 客户端上都会抛 configuration）。
     */
    boolean hasInboundOverrides() {
        return hasAppKey() || hasSuite() || hasMerchantPrivateKey() || hasPlatformPublicKey();
    }

    /** 是否无任何有效覆盖（与 {@link #none()} 值等价）。 */
    public boolean isEmpty() {
        return !hasAppKey() && !hasSuite() && !hasMerchantPrivateKey()
                && !hasPlatformPublicKey() && !hasExpiredSeconds()
                && !hasServerRoot() && !hasConnectTimeout() && !hasReadTimeout()
                && !hasRequestId() && !hasSubMchId();
    }

    public static final class Builder {

        private String appKey;
        private String suite;
        private String merchantPrivateKey;
        private String platformPublicKey;
        private long expiredSeconds;
        private String serverRoot;
        private int connectTimeout;
        private int readTimeout;
        private String requestId;
        private String subMchId;

        public Builder appKey(String appKey) {
            this.appKey = appKey;
            return this;
        }

        public Builder suite(String suite) {
            this.suite = suite;
            return this;
        }

        public Builder merchantPrivateKey(String merchantPrivateKey) {
            this.merchantPrivateKey = merchantPrivateKey;
            return this;
        }

        public Builder platformPublicKey(String platformPublicKey) {
            this.platformPublicKey = platformPublicKey;
            return this;
        }

        public Builder expiredSeconds(long expiredSeconds) {
            if (expiredSeconds < 0) {
                throw WopError.configuration("expiredSeconds 不能为负数");
            }
            this.expiredSeconds = expiredSeconds;
            return this;
        }

        public Builder serverRoot(String serverRoot) {
            this.serverRoot = serverRoot;
            return this;
        }

        public Builder connectTimeout(int connectTimeout) {
            if (connectTimeout < 0) {
                throw WopError.configuration("connectTimeout 不能为负数");
            }
            this.connectTimeout = connectTimeout;
            return this;
        }

        public Builder readTimeout(int readTimeout) {
            if (readTimeout < 0) {
                throw WopError.configuration("readTimeout 不能为负数");
            }
            this.readTimeout = readTimeout;
            return this;
        }

        /**
         * 商户请求标识（wop-specs 附录 I：不参与签名的透传头，须为不含个人数据的不透明关联标识）；
         * null 或空白 → 缺省生成 UUID（头恒存在）；构造时校验：控制字符（trim 前原值扫描，CR/LF/NUL/DEL）
         * 与超长（trim 后 UTF-8 字节 &gt; 128）均抛配置异常。
         */
        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        /**
         * 子商户身份（ISV D-13）：出向写入 {@code x-wop-sub-mch-id} 并纳入 signedHeaders，
         * 值 = 子商户 {@code plf_co_id}；null/空白 = 未设置（应用自身身份，头缺席）。
         * 构造时校验：仅可打印 ASCII（0x20~0x7E，防头注入/签名歧义）、trim 后无内部空白、
         * trim 后长度 ≤ 128；违规抛配置异常。
         */
        public Builder subMchId(String subMchId) {
            this.subMchId = subMchId;
            return this;
        }

        public WopRequestOptions build() {
            validateRequestId(requestId);
            validateSubMchId(subMchId);
            return new WopRequestOptions(appKey, suite, merchantPrivateKey, platformPublicKey,
                    expiredSeconds, serverRoot, connectTimeout, readTimeout, requestId, subMchId);
        }

        private static void validateRequestId(String requestId) {
            if (requestId == null) {
                return;
            }
            // 先查原始值（trim 前）防首尾控制字符注入 CR/LF/NUL/DEL（附录 I/I2）
            for (int i = 0; i < requestId.length(); i++) {
                char c = requestId.charAt(i);
                if (c < 0x20 || c == 0x7f) {
                    throw WopError.configuration("requestId 含控制字符（防头注入）: " + (int) c);
                }
            }
            String trimmed = requestId.trim();
            if (trimmed.isEmpty()) {
                return;
            }
            // 附录 I/I2：长度上限按 trim 后 UTF-8 编码字节数（网关 header 缓冲按字节计；
            // 非 ASCII 下 UTF-16 计长会低估线上字节，须显式编码后计量）
            int utf8Length = trimmed.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            if (utf8Length > 128) {
                throw WopError.configuration("requestId UTF-8 字节长度不能超过 128（实际 " + utf8Length + "）");
            }
        }

        /** 子商户头值守卫：可打印 ASCII、无内部空白、trim 后 ≤128（防头注入与签名/身份歧义）。 */
        private static void validateSubMchId(String subMchId) {
            if (subMchId == null) {
                return;
            }
            // 仅可打印 ASCII：CR/LF/NUL 等控制字符防头注入，非 ASCII 在 Servlet/OkHttp 头编码下不可靠
            for (int i = 0; i < subMchId.length(); i++) {
                char c = subMchId.charAt(i);
                if (c < 0x20 || c > 0x7e) {
                    throw WopError.configuration("subMchId 须为可打印 ASCII（防头注入/签名歧义）: " + (int) c);
                }
            }
            String trimmed = subMchId.trim();
            if (trimmed.isEmpty()) {
                return;
            }
            // 网关 canonical 的 trimall 会折叠内部空白，而身份查询只做 trim——内部空白破坏签名与身份一一对应
            if (trimmed.indexOf(' ') >= 0) {
                throw WopError.configuration("subMchId 不能包含内部空白");
            }
            if (trimmed.length() > 128) {
                throw WopError.configuration("subMchId 长度不能超过 128（实际 " + trimmed.length() + "）");
            }
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof WopRequestOptions)) {
            return false;
        }
        WopRequestOptions that = (WopRequestOptions) o;
        return expiredSeconds == that.expiredSeconds
                && connectTimeout == that.connectTimeout
                && readTimeout == that.readTimeout
                && Objects.equals(appKey, that.appKey)
                && Objects.equals(suite, that.suite)
                && Objects.equals(merchantPrivateKey, that.merchantPrivateKey)
                && Objects.equals(platformPublicKey, that.platformPublicKey)
                && Objects.equals(serverRoot, that.serverRoot)
                && Objects.equals(requestId, that.requestId)
                && Objects.equals(subMchId, that.subMchId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(appKey, suite, merchantPrivateKey, platformPublicKey, expiredSeconds,
                serverRoot, connectTimeout, readTimeout, requestId, subMchId);
    }

    /** K16：日志/toString 凭证打码。 */
    @Override
    public String toString() {
        return "WopRequestOptions[appKey=" + appKey + ", suite=" + suite
                + ", merchantPrivateKey=****, platformPublicKey=****"
                + ", expiredSeconds=" + expiredSeconds
                + ", serverRoot=" + serverRoot
                + ", connectTimeout=" + connectTimeout
                + ", readTimeout=" + readTimeout
                + ", requestId=" + requestId
                + ", subMchId=" + subMchId + ']';
    }
}
