package com.wanlianyida.wop.jdkhttp;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * java.net（HttpURLConnection）Transport 适配器（零额外依赖，薄封装）。
 * baseUrl 为空时要求 draft.path 为绝对 URL。
 * <p>
 * Java 8 floor：JDK 11 的 java.net.http 在 -release 8 下不可用，本适配器改建于
 * JDK 1.1 起可用的 HttpURLConnection。行为契约（头/体映射、11MB 流式上限、
 * HEAD 归一为 GET、错误透传）与原 java.net.http 版本一致；差异仅一处——
 * {@link HttpURLConnection#setRequestMethod(String)} 只接受标准方法
 * （GET/HEAD/POST/PUT/DELETE/OPTIONS/TRACE），PATCH 等扩展方法在此显式拒绝
 * （fail fast、不开网络），需要扩展方法的调用方请改用 okhttp/unirest 适配器。
 */
public final class JdkHttpTransport implements Transport {

    /** 响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读，D5 精神）。 */
    public static final int MAX_RESPONSE_BYTES = 11 << 20;

    /** 连接超时（毫秒），对应原 HttpClient.newBuilder().connectTimeout(10s)。 */
    private static final int CONNECT_TIMEOUT_MS = 10_000;

    /**
     * 方法白名单（前后留空格便于 contains 匹配）：即 HttpURLConnection.setRequestMethod
     * 文档列出的标准方法集；PATCH/PROPFIND 等扩展方法被其拒绝（ProtocolException），
     * 这里提前到开连接之前显式拒绝，给出可操作错误。
     */
    private static final String SUPPORTED_METHODS = " GET HEAD POST PUT DELETE OPTIONS TRACE ";
    private final String baseUrl;

    public JdkHttpTransport() {
        this(null);
    }

    public JdkHttpTransport(String baseUrl) {
        this.baseUrl = trimBaseUrl(baseUrl);
    }

    @Override
    public TransportResponse send(RequestDraft draft) {
        if (Thread.currentThread().isInterrupted()) {
            throw new WopSdkException("JDK HttpURLConnection 传输被中断");
        }
        if (!isSupportedMethod(draft.method())) {
            throw new WopSdkException("JDK HttpURLConnection 不支持方法 " + draft.method()
                    + "：仅接受标准方法（GET/HEAD/POST/PUT/DELETE/OPTIONS/TRACE），"
                    + "PATCH 等扩展方法请改用 okhttp/unirest 适配器");
        }
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(resolve(draft)).openConnection();
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);   // 与 java.net.http 默认一致：不跟随重定向
            draft.headers().forEach(connection::addRequestProperty);
            boolean normalizedGet = "GET".equals(draft.method()) || "HEAD".equals(draft.method());
            if (normalizedGet) {
                // GET/HEAD 归一：无实体（保留原 HttpClient 归一语义）
                connection.setRequestMethod("GET");
            } else {
                connection.setRequestMethod(draft.method());
                connection.setDoOutput(true);
                byte[] wire = draft.wireBody() == null ? new byte[0] : draft.wireBody();
                connection.setFixedLengthStreamingMode(wire.length);
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(wire);
                }
            }
            int status = connection.getResponseCode();
            if (Thread.currentThread().isInterrupted()) {
                // HttpURLConnection 阻塞 I/O 不响应中断；阶段边界（响应状态已到）检测
                // 中断标志并失败，对齐原 java.net.http 版「恢复标志并失败」的语义。
                throw new WopSdkException("JDK HttpURLConnection 传输被中断");
            }
            byte[] body = readEntity(connection, status);
            return new TransportResponse(status, collectHeaders(connection), body);
        } catch (IOException e) {
            throw new WopSdkException("JDK HttpURLConnection 传输失败: " + e.getMessage(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /** 响应头 → 小写键首个值（送入 verify 层的头名恒小写）。 */
    private static Map<String, String> collectHeaders(HttpURLConnection connection) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : connection.getHeaderFields().entrySet()) {
            // 状态行条目 key=null（无值可取）；非 null key 的 value 列表恒非空（HttpURLConnection 契约）
            if (entry.getKey() != null) {
                headers.put(entry.getKey().toLowerCase(), entry.getValue().get(0));
            }
        }
        return headers;
    }

    /** 读取响应实体：错误流优先；错误状态无 error stream 视为服务器未写错误体，按空 body
     * 透传（此时 getInputStream() 会抛 IOException，不可调用）；204/304 禁止实体，恒空数组；
     * 正常流走 11MB 上限的流式读取。完读后台账校验 Content-Length：HttpURLConnection
     * 对提前 EOF 静默返回 -1（与 java.net.http 的「too few bytes returned」不同），
     * 截断须在此显式拦截。 */
    private static byte[] readEntity(HttpURLConnection connection, int status) throws IOException {
        InputStream stream = connection.getErrorStream();
        if (stream == null && !isBodyless(status) && status < 400) {
            stream = connection.getInputStream();
        }
        return verifyLength(connection, status, stream == null ? new byte[0] : readBodyLimited(stream));
    }

    /** 实收长度与 Content-Length 声明不符（服务端提前断流）→ 协议类明确异常。
     * 204/304 等禁止实体的状态跳过比对：部分网关在无实体响应上仍带 stale
     * Content-Length 头，空 body 是合法终态而非截断。 */
    private static byte[] verifyLength(HttpURLConnection connection, int status, byte[] body) {
        if (isBodyless(status)) {
            return body;
        }
        long declared = connection.getContentLengthLong();
        if (declared >= 0 && body.length != declared) {
            throw new WopSdkException("JDK HttpURLConnection 响应体被截断: 声明 " + declared
                    + " 字节, 实收 " + body.length);
        }
        return body;
    }

    /** RFC 9110 禁止携带实体的状态码：204 No Content / 304 Not Modified。 */
    private static boolean isBodyless(int status) {
        return status == HttpURLConnection.HTTP_NO_CONTENT || status == HttpURLConnection.HTTP_NOT_MODIFIED;
    }

    private static boolean isSupportedMethod(String method) {
        return SUPPORTED_METHODS.contains(" " + method + " ");
    }

    /** 流式读取响应体：逐块计数，超 {@link #MAX_RESPONSE_BYTES} 即中止并抛协议类异常（不做整体缓冲）。 */
    private static byte[] readBodyLimited(InputStream stream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = stream.read(chunk)) != -1) {
            total += read;
            if (total > MAX_RESPONSE_BYTES) {
                throw new WopSdkException("JDK HttpURLConnection 响应体超过 " + MAX_RESPONSE_BYTES + " 字节上限");
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
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return null;
        }
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}
