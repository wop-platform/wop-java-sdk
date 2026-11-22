package com.wanlianyida.wop;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public final class TransportResponse {

    private final int statusCode;

    /** 响应头（名小写，大小写不敏感查找）。 */
    private final Map<String, String> headers;

    private final byte[] body;

    public TransportResponse(int statusCode, Map<String, String> headers, byte[] body) {
        this.statusCode = statusCode;
        Map<String, String> lower = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        lower.putAll(headers);
        this.headers = Collections.unmodifiableMap(lower);
        this.body = body;
    }

    public int statusCode() {
        return statusCode;
    }

    public Map<String, String> headers() {
        return headers;
    }

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
