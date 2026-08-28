package com.wopplatform.wopsdk.jdkhttp;

import com.wopplatform.wopsdk.RequestDraft;
import com.wopplatform.wopsdk.Transport;
import com.wopplatform.wopsdk.TransportResponse;
import com.wopplatform.wopsdk.WopSdkException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * java.net.http Transport 适配器（零额外依赖，薄封装）。
 * baseUrl 为空时要求 draft.path 为绝对 URL。
 */
public final class JdkHttpTransport implements Transport {

    private final HttpClient client;
    private final String baseUrl;

    public JdkHttpTransport() {
        this(null);
    }

    public JdkHttpTransport(String baseUrl) {
        this(baseUrl, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public JdkHttpTransport(String baseUrl, HttpClient client) {
        this.baseUrl = trimBaseUrl(baseUrl);
        this.client = client;
    }

    @Override
    public TransportResponse send(RequestDraft draft) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(resolve(draft)));
        HttpRequest.BodyPublisher publisher = draft.wireBody() == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(draft.wireBody());
        builder.method("GET".equals(draft.method()) || "HEAD".equals(draft.method())
                ? "GET" : draft.method(), publisher);
        draft.headers().forEach(builder::header);

        HttpResponse<byte[]> response;
        try {
            response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new WopSdkException("JDK HttpClient 传输失败: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WopSdkException("JDK HttpClient 传输被中断", e);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) {
                headers.put(name.toLowerCase(), values.get(0));
            }
        });
        return new TransportResponse(response.statusCode(), headers, response.body());
    }

    private String resolve(RequestDraft draft) {
        String path = draft.path();
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (baseUrl == null) {
            throw new WopSdkException("path 非绝对 URL 且未配置 baseUrl: " + path);
        }
        return baseUrl + (path.startsWith("/") ? path : "/" + path);
    }

    private static String trimBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return null;
        }
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}
