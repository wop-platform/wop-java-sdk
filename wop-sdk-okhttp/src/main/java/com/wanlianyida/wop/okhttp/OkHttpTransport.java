package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import com.wanlianyida.wop.config.ConfigUrlUtils;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.BufferedSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * OkHttp Transport 适配器（薄封装：draft → okhttp Request → TransportResponse）。
 * <p>
 * okhttp 依赖 scope=provided（商户自带版本）；baseUrl 为空时要求 draft.path 为绝对 URL。
 */
public final class OkHttpTransport implements Transport {

    /** 响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读，D5 精神）。 */
    public static final int MAX_RESPONSE_BYTES = 11 << 20;

    private static final MediaType OCTET_STREAM = MediaType.parse("application/octet-stream");

    private final OkHttpClient client;
    private final String baseUrl;

    public OkHttpTransport() {
        this(null, defaultClient());
    }

    public OkHttpTransport(String baseUrl) {
        this(baseUrl, defaultClient());
    }

    public OkHttpTransport(String baseUrl, OkHttpClient client) {
        this.baseUrl = trimBaseUrl(baseUrl);
        this.client = client;
    }

    private static OkHttpClient defaultClient() {
        return new OkHttpClient.Builder().followRedirects(false).build();
    }

    @Override
    public boolean supportsTransportCall() {
        return true;
    }

    @Override
    public TransportResponse send(RequestDraft draft) {
        return send(draft, TransportCall.empty());
    }

    @Override
    public TransportResponse send(RequestDraft draft, TransportCall call) {
        OkHttpClient effective = clientForCall(call);
        Request.Builder builder = new Request.Builder().url(resolve(draft, call));
        RequestBody requestBody = draft.wireBody() == null
                ? null
                : RequestBody.create(draft.wireBody(), OCTET_STREAM);
        builder.method(draft.method(), "GET".equals(draft.method()) || "HEAD".equals(draft.method())
                ? null : requestBody);
        draft.headers().forEach(builder::addHeader);

        try (Response response = effective.newCall(builder.build()).execute()) {
            Map<String, String> headers = new LinkedHashMap<>();
            response.headers().forEach(pair -> headers.put(pair.component1().toLowerCase(), pair.component2()));
            byte[] body = readBodyLimited(response.body());
            return new TransportResponse(response.code(), headers, body);
        } catch (IOException e) {
            throw new WopSdkException("OkHttp 传输失败: " + e.getMessage(), e);
        }
    }

    /** 流式读取响应体：Content-Length 预检 + 逐块计数，超 {@link #MAX_RESPONSE_BYTES} 即中止并抛协议类异常。 */
    private static byte[] readBodyLimited(ResponseBody responseBody) throws IOException {
        long declared = responseBody.contentLength();
        if (declared > MAX_RESPONSE_BYTES) {
            throw new WopSdkException(
                    "OkHttp 响应体超过 " + MAX_RESPONSE_BYTES + " 字节上限（Content-Length: " + declared + "）");
        }
        BufferedSource source = responseBody.source();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = source.read(chunk)) != -1) {
            total += read;
            if (total > MAX_RESPONSE_BYTES) {
                throw new WopSdkException("OkHttp 响应体超过 " + MAX_RESPONSE_BYTES + " 字节上限");
            }
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    private OkHttpClient clientForCall(TransportCall call) {
        OkHttpClient.Builder builder = client.newBuilder().followRedirects(false);
        if (call == null || call == TransportCall.empty()) {
            return builder.build();
        }
        if (call.connectTimeoutMillis() > 0) {
            builder.connectTimeout(call.connectTimeoutMillis(), TimeUnit.MILLISECONDS);
        }
        if (call.readTimeoutMillis() > 0) {
            builder.readTimeout(call.readTimeoutMillis(), TimeUnit.MILLISECONDS);
        }
        return builder.build();
    }

    private String resolve(RequestDraft draft, TransportCall call) {
        if (call != null && call.serverRoot() != null && !call.serverRoot().isEmpty()) {
            return ConfigUrlUtils.joinUrl(call.serverRoot(), draft.path());
        }
        String path = draft.path();
        if (path.startsWith("http")) {
            return path;
        }
        if (baseUrl == null) {
            throw new WopSdkException("path 非绝对 URL 且未配置 baseUrl: " + path);
        }
        return baseUrl + (path.startsWith("/") ? path : "/" + path);
    }

    private static String trimBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return null;
        }
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}
