package com.wanlianyida.wop;

import java.util.Objects;

/**
 * 请求级覆盖（§6.1）；未设置字段沿用全局 JSON 配置。
 */
public final class WopRequestOptions {

    private static final WopRequestOptions NONE = new WopRequestOptions(
            null, null, null, null, 0L, null, 0, 0, null);

    private final String appKey;
    private final String suite;
    private final String merchantPrivateKey;
    private final String platformPublicKey;
    private final long expiredSeconds;
    private final String serverRoot;
    private final int connectTimeout;
    private final int readTimeout;
    private final String requestId;

    private WopRequestOptions(String appKey, String suite, String merchantPrivateKey,
                              String platformPublicKey, long expiredSeconds, String serverRoot,
                              int connectTimeout, int readTimeout, String requestId) {
        this.appKey = appKey;
        this.suite = suite;
        this.merchantPrivateKey = merchantPrivateKey;
        this.platformPublicKey = platformPublicKey;
        this.expiredSeconds = expiredSeconds;
        this.serverRoot = serverRoot;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.requestId = requestId;
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

    /**
     * 解析后 requestId 值：非空时返回 trim 后的值（控制字符在 build 时已校验）；
     * null 或空白时返回 null（表示透传头缺席）。
     */
    String resolvedRequestId() {
        if (requestId == null) {
            return null;
        }
        String trimmed = requestId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** 是否无任何有效覆盖（与 {@link #none()} 值等价）。 */
    public boolean isEmpty() {
        return !hasAppKey() && !hasSuite() && !hasMerchantPrivateKey()
                && !hasPlatformPublicKey() && !hasExpiredSeconds()
                && !hasServerRoot() && !hasConnectTimeout() && !hasReadTimeout()
                && !hasRequestId();
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
         * 商户请求标识（透传网关用，不参与签名）；
         * null 或空白 → 不写入 {@code x-wop-request-id} 头；含控制字符（CR/LF 等）抛出配置异常。
         */
        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public WopRequestOptions build() {
            validateRequestId(requestId);
            return new WopRequestOptions(appKey, suite, merchantPrivateKey, platformPublicKey,
                    expiredSeconds, serverRoot, connectTimeout, readTimeout, requestId);
        }

        private static void validateRequestId(String requestId) {
            if (requestId == null) {
                return;
            }
            String trimmed = requestId.trim();
            if (trimmed.isEmpty()) {
                return;
            }
            for (int i = 0; i < trimmed.length(); i++) {
                char c = trimmed.charAt(i);
                if (c < 0x20 || c == 0x7f) {
                    throw WopError.configuration("requestId 含控制字符（防头注入）: " + (int) c);
                }
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
                && Objects.equals(requestId, that.requestId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(appKey, suite, merchantPrivateKey, platformPublicKey, expiredSeconds,
                serverRoot, connectTimeout, readTimeout, requestId);
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
                + ", requestId=" + requestId + ']';
    }
}
