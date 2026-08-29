package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
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

    private String resolve(RequestDraft draft) {
        String path = draft.path();
        if (path.startsWith("http")) {   // http:/ 与 https:// 同判
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
