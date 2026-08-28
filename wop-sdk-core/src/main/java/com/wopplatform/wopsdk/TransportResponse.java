package com.wopplatform.wopsdk;

import java.util.Map;

/**
 * Transport 适配器返回的响应快照（头名已小写化）。
 *
 * @param statusCode HTTP 状态码
 * @param headers    响应头（名小写）
 * @param body       响应体字节
 */
public record TransportResponse(int statusCode, Map<String, String> headers, byte[] body) {

    public TransportResponse {
        Map<String, String> lower = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        lower.putAll(headers);
        headers = java.util.Collections.unmodifiableMap(lower);
    }
}
