package com.wanlianyida.wop.config;

import java.util.Objects;

/** HTTP 客户端全局参数（毫秒/次数，§3.3 httpClient）。 */
public final class HttpClientSettings {

    public static final int DEFAULT_CONNECT_TIMEOUT = 10_000;
    public static final int DEFAULT_READ_TIMEOUT = 30_000;
    public static final int DEFAULT_MAX_RETRY_COUNT = 3;

    private final int connectTimeout;
    private final int readTimeout;
    private final int maxRetryCount;

    public HttpClientSettings(int connectTimeout, int readTimeout, int maxRetryCount) {
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.maxRetryCount = maxRetryCount;
    }

    /** 默认超时与重试上限。 */
    public static HttpClientSettings defaults() {
        return new HttpClientSettings(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, DEFAULT_MAX_RETRY_COUNT);
    }

    public int connectTimeout() {
        return connectTimeout;
    }

    public int readTimeout() {
        return readTimeout;
    }

    public int maxRetryCount() {
        return maxRetryCount;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof HttpClientSettings)) {
            return false;
        }
        HttpClientSettings that = (HttpClientSettings) o;
        return connectTimeout == that.connectTimeout
                && readTimeout == that.readTimeout
                && maxRetryCount == that.maxRetryCount;
    }

    @Override
    public int hashCode() {
        return Objects.hash(connectTimeout, readTimeout, maxRetryCount);
    }

    @Override
    public String toString() {
        return "HttpClientSettings{connectTimeout=" + connectTimeout
                + ", readTimeout=" + readTimeout + ", maxRetryCount=" + maxRetryCount + '}';
    }
}
