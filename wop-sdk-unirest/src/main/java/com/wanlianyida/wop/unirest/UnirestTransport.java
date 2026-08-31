package com.wanlianyida.wop.unirest;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import kong.unirest.core.Config;
import kong.unirest.core.Header;
import kong.unirest.core.Headers;
import kong.unirest.core.HttpRequest;
import kong.unirest.core.HttpRequestWithBody;
import kong.unirest.core.RawResponse;
import kong.unirest.core.UnirestException;
import kong.unirest.core.UnirestInstance;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Unirest 4.x（{@code kong.unirest.core}）Transport 适配器（薄封装：draft → unirest 请求 → TransportResponse）。
 * <p>
 * unirest 依赖 scope=provided（商户自带版本）；baseUrl 为空时要求 draft.path 为绝对 URL。
 * 响应体经 {@link RawResponse#getContent()} 流式限量读取（thenConsume），不使用 {@code asBytes()} 全量缓冲。
 */
public final class UnirestTransport implements Transport {

    /** 响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读，D5 精神）。 */
    public static final int MAX_RESPONSE_BYTES = 11 << 20;

    private static final String OCTET_STREAM = "application/octet-stream";

    private final UnirestInstance unirest;
    private final String baseUrl;

    public UnirestTransport() {
        this(null);
    }

    public UnirestTransport(String baseUrl) {
        this(baseUrl, new UnirestInstance(new Config().connectTimeout(10_000)
                // 停发 Accept-Encoding:gzip 协商——JDK HttpClient 不自动解压，防网关回 gzip 交付压缩字节
                .requestCompression(false)));
    }

    public UnirestTransport(String baseUrl, UnirestInstance unirest) {
        this.baseUrl = trimBaseUrl(baseUrl);
        this.unirest = unirest;
    }

    @Override
    public TransportResponse send(RequestDraft draft) {
        HttpRequestWithBody request = unirest.request(draft.method(), resolve(draft));
        draft.headers().forEach(request::header);
        byte[] wire = draft.wireBody();
        // body 存在于 body() 返回的 RequestBodyEntity（包装对象）中，后续执行必须走该引用
        HttpRequest<?> executable = request;
        if (wire != null && !"GET".equals(draft.method()) && !"HEAD".equals(draft.method())) {
            if (!draft.headers().containsKey("content-type")) {
                request.contentType(OCTET_STREAM);
            }
            executable = request.body(wire);
        }

        AtomicInteger status = new AtomicInteger();
        AtomicReference<Headers> respHeaders = new AtomicReference<>();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        AtomicBoolean overflow = new AtomicBoolean();
        try {
            executable.thenConsume(raw -> {
                status.set(raw.getStatus());
                respHeaders.set(raw.getHeaders());
                readBodyLimited(raw, buffer, overflow);
            });
        } catch (UnirestException e) {
            throw new WopSdkException("Unirest 传输失败: " + e.getMessage(), e);
        }
        if (overflow.get()) {
            throw new WopSdkException("Unirest 响应体超过 " + MAX_RESPONSE_BYTES + " 字节上限");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        String declaredLength = null;
        for (Header h : respHeaders.get().all()) {
            String name = h.getName().toLowerCase();
            headers.put(name, h.getValue());
            if ("content-length".equals(name)) {
                declaredLength = h.getValue();
            }
        }
        // JDK HttpClient 对传输中断连静默返回已读字节，此处按声明长度校验防截断体混入上层
        if (declaredLength != null && buffer.size() != Integer.parseInt(declaredLength.trim())) {
            throw new WopSdkException("Unirest 响应体截断: Content-Length 声明 "
                    + declaredLength.trim() + "，实收 " + buffer.size());
        }
        return new TransportResponse(status.get(), headers, buffer.toByteArray());
    }

    /** 流式读取响应体：逐块计数，超 {@link #MAX_RESPONSE_BYTES} 置位并中止（不做整体缓冲）。无实体（null 流）按空 body 处理。 */
    private static void readBodyLimited(RawResponse raw, ByteArrayOutputStream buffer, AtomicBoolean overflow) {
        InputStream stream = raw.getContent();
        if (stream == null) {
            return;
        }
        try {
            byte[] chunk = new byte[8192];
            int read;
            while ((read = stream.read(chunk)) != -1) {
                if (buffer.size() + read > MAX_RESPONSE_BYTES) {
                    overflow.set(true);
                    return;
                }
                buffer.write(chunk, 0, read);
            }
        } catch (IOException e) {
            throw new UnirestException(e);
        } finally {
            try {
                stream.close();
            } catch (IOException ignored) {
                // 关闭失败不影响已读结果
            }
        }
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
