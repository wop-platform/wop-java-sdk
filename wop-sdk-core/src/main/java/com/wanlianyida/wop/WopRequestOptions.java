package com.wanlianyida.wop;

import java.util.Objects;

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

    public long expiredSeconds() {
        return expiredSeconds;
    }

    public String serverRoot() {
        return serverRoot;
    }

    public int connectTimeout() {
        return connectTimeout;
    }

    public int readTimeout() {
        return readTimeout;
    }

    public String requestId() {
        return requestId;
    }

    public String subMchId() {
        return subMchId;
    }

    public boolean hasAppKey() {
        return appKey != null && !appKey.trim().isEmpty();
    }

    public boolean hasSuite() {
        return suite != null && !suite.trim().isEmpty();
    }

    public boolean hasMerchantPrivateKey() {
        return merchantPrivateKey != null && !merchantPrivateKey.trim().isEmpty();
    }

    public boolean hasPlatformPublicKey() {
        return platformPublicKey != null && !platformPublicKey.trim().isEmpty();
    }

    public boolean hasExpiredSeconds() {
        return expiredSeconds > 0;
    }

    public boolean hasServerRoot() {
        return serverRoot != null && !serverRoot.trim().isEmpty();
    }

    public boolean hasConnectTimeout() {
        return connectTimeout > 0;
    }

    public boolean hasReadTimeout() {
        return readTimeout > 0;
    }

    public boolean hasRequestId() {
        return requestId != null && !requestId.trim().isEmpty();
    }

    public boolean hasSubMchId() {
        return subMchId != null && !subMchId.trim().isEmpty();
    }

    String resolvedRequestId() {
        if (requestId == null) {
            return null;
        }
        String trimmed = requestId.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

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

        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

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

        private static void validateSubMchId(String subMchId) {
            if (subMchId == null) {
                return;
            }
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
