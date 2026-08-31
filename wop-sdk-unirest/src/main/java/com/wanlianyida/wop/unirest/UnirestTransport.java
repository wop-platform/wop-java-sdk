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
                // 停发 Accept-Encoding:gzip 协商——JavaResponse.getContent() 对 gzip 响应透明解压，
                // 解压后长度≠声明 Content-Length（压缩大小），截断校验会误杀所有 gzip 响应
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
        // consumer 内不能抛：JavaClient.transformBody 会把 RuntimeException 吞成 BasicResponse 永不传播，
        // 读流错误存引用，thenConsume 返回后统一抛出
        AtomicReference<IOException> readError = new AtomicReference<>();
        try {
            executable.thenConsume(raw -> {
                status.set(raw.getStatus());
                respHeaders.set(raw.getHeaders());
                readBodyLimited(raw, buffer, overflow, readError);
            });
        } catch (UnirestException e) {
            throw new WopSdkException("Unirest 传输失败: " + e.getMessage(), e);
        }
        IOException streamFailure = readError.get();
        if (streamFailure != null) {
            throw new WopSdkException("Unirest 传输失败: " + streamFailure.getMessage(), streamFailure);
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
        // 畸形/负值 Content-Length 是头部协议违规，无条件落 WopSdkException 边界；
        // 超限预检与截断等值校验均须有体语义（HEAD/1xx/204/205/304 的 CL 描述对应
        // GET 表示长度，RFC 9110 §6.4/§9.3.2），无体时不参与读侧约束
        long declared = -1;
        if (declaredLength != null) {
            declared = parseNonNegativeLength(declaredLength);
        }
        boolean expectBody = bodyExpected(draft.method(), status.get());
        if (expectBody && declared > MAX_RESPONSE_BYTES) {
            throw new WopSdkException("Unirest 响应体声明 " + declared
                    + " 字节，超过 " + MAX_RESPONSE_BYTES + " 上限");
        }
        if (overflow.get()) {
            throw new WopSdkException("Unirest 响应体超过 " + MAX_RESPONSE_BYTES + " 字节上限");
        }
        // JDK HttpClient 对传输中断连静默返回已读字节，此处按声明长度校验防截断体混入上层
        if (expectBody && declared >= 0 && buffer.size() != declared) {
            throw new WopSdkException("Unirest 响应体截断: Content-Length 声明 "
                    + declared + "，实收 " + buffer.size());
        }
        return new TransportResponse(status.get(), headers, buffer.toByteArray());
    }

    /** Content-Length 非负 long 解析；畸形/负值抛 {@link WopSdkException}（保持传输边界异常语义）。 */
    private static long parseNonNegativeLength(String raw) {
        long value;
        try {
            value = Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            throw new WopSdkException("Unirest 响应 Content-Length 畸形: '" + raw.trim() + "'");
        }
        if (value < 0) {
            throw new WopSdkException("Unirest 响应 Content-Length 畸形: '" + raw.trim() + "'");
        }
        return value;
    }

    /** 语义上是否应有响应体：HEAD 无体；1xx/204/205/304 无体（RFC 9110 §6.4）。 */
    private static boolean bodyExpected(String method, int status) {
        if ("HEAD".equals(method)) {
            return false;
        }
        return status >= 200 && status != 204 && status != 205 && status != 304;
    }

    /** 流式读取响应体：逐块计数，超 {@link #MAX_RESPONSE_BYTES} 置位并中止（不做整体缓冲）。无实体（null 流）按空 body 处理。
     * 读流 {@link IOException} 存入 {@code readError} 不抛出——抛出会被 JavaClient.transformBody 吞掉（见 send 内注释）。 */
    private static void readBodyLimited(RawResponse raw, ByteArrayOutputStream buffer, AtomicBoolean overflow,
            AtomicReference<IOException> readError) {
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
            readError.set(e);
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
