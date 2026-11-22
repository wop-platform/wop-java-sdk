package com.wanlianyida.wop;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Transport 适配器返回的响应快照（头名已小写化）。
 * <p>
 * 不可变值对象（record 等价语义：equals/hashCode 按全部字段，数组字段引用比较；
 * headers 构造时防御性拷贝为大小写不敏感的不可变视图）。
 */
public final class TransportResponse {

    /** HTTP 状态码。 */
    private final int statusCode;

    /** 响应头（名小写，大小写不敏感查找）。 */
    private final Map<String, String> headers;

    /** 响应体字节。 */
    private final byte[] body;

    public TransportResponse(int statusCode, Map<String, String> headers, byte[] body) {
        this.statusCode = statusCode;
        Map<String, String> lower = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        lower.putAll(headers);
        this.headers = Collections.unmodifiableMap(lower);
        this.body = body;
    }

    /** HTTP 状态码。 */
    public int statusCode() {
        return statusCode;
    }

    /** 响应头（名小写，大小写不敏感查找），不可变。 */
    public Map<String, String> headers() {
        return headers;
    }

    /** 响应体字节。 */
    public byte[] body() {
        return body;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TransportResponse)) {
            return false;
        }
        TransportResponse that = (TransportResponse) o;
        return statusCode == that.statusCode && Objects.equals(headers, that.headers)
                && Objects.equals(body, that.body);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statusCode, headers, body);
    }

    @Override
    public String toString() {
        return "TransportResponse[statusCode=" + statusCode + ", headers=" + headers
                + ", body=" + body + "]";
    }
}
