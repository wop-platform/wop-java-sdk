package com.wopplatform.wopsdk.okhttp;

import com.wopplatform.wopsdk.RequestDraft;
import com.wopplatform.wopsdk.Transport;
import com.wopplatform.wopsdk.TransportResponse;
import com.wopplatform.wopsdk.WopSdkException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OkHttp Transport 适配器（薄封装：draft → okhttp Request → TransportResponse）。
 * <p>
 * okhttp 依赖 scope=provided（商户自带版本）；baseUrl 为空时要求 draft.path 为绝对 URL。
 */
public final class OkHttpTransport implements Transport {

    private static final MediaType OCTET_STREAM = MediaType.parse("application/octet-stream");

    private final OkHttpClient client;
    private final String baseUrl;

    public OkHttpTransport() {
        this(null, new OkHttpClient());
    }

    public OkHttpTransport(String baseUrl) {
        this(baseUrl, new OkHttpClient());
    }

    public OkHttpTransport(String baseUrl, OkHttpClient client) {
        this.baseUrl = trimBaseUrl(baseUrl);
        this.client = client;
    }

    @Override
    public TransportResponse send(RequestDraft draft) {
        Request.Builder builder = new Request.Builder().url(resolve(draft));
        RequestBody requestBody = draft.wireBody() == null
                ? null
                : RequestBody.create(draft.wireBody(), OCTET_STREAM);
        builder.method(draft.method(), "GET".equals(draft.method()) || "HEAD".equals(draft.method())
                ? null : requestBody);
        draft.headers().forEach(builder::addHeader);

        try (Response response = client.newCall(builder.build()).execute()) {
            Map<String, String> headers = new LinkedHashMap<>();
            response.headers().forEach(pair -> headers.put(pair.component1().toLowerCase(), pair.component2()));
            byte[] body = response.body() == null ? new byte[0] : response.body().bytes();
            return new TransportResponse(response.code(), headers, body);
        } catch (IOException e) {
            throw new WopSdkException("OkHttp 传输失败: " + e.getMessage(), e);
        }
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
