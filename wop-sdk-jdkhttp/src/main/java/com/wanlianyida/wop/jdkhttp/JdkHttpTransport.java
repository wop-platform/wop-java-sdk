package com.wanlianyida.wop.jdkhttp;

import com.wanlianyida.wop.RequestDraft;
import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.TransportResponse;
import com.wanlianyida.wop.WopSdkException;
import com.wanlianyida.wop.config.ConfigUrlUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JdkHttpTransport implements Transport {

    public static final int MAX_RESPONSE_BYTES = 11 << 20;

    private static final int CONNECT_TIMEOUT_MS = 10_000;

    /** 读超时（毫秒，P1 默认 30s）。 */
    private static final int READ_TIMEOUT_MS = 30_000;

    private static final String SUPPORTED_METHODS = " GET HEAD POST PUT DELETE OPTIONS TRACE ";
    private final String baseUrl;

    public JdkHttpTransport() {
        this(null);
    }

    public JdkHttpTransport(String baseUrl) {
        this.baseUrl = trimBaseUrl(baseUrl);
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
        if (Thread.currentThread().isInterrupted()) {
            throw new WopSdkException("JDK HttpURLConnection 传输被中断");
        }
        if (!isSupportedMethod(draft.method())) {
            throw new WopSdkException("JDK HttpURLConnection 不支持方法 " + draft.method()
                    + "：仅接受标准方法（GET/HEAD/POST/PUT/DELETE/OPTIONS/TRACE），"
                    + "PATCH 等扩展方法请改用 okhttp/unirest 适配器");
        }
        int connectTimeout = resolveTimeout(call == null ? TransportCall.USE_DEFAULT : call.connectTimeoutMillis(),
                CONNECT_TIMEOUT_MS);
        int readTimeout = resolveTimeout(call == null ? TransportCall.USE_DEFAULT : call.readTimeoutMillis(),
                READ_TIMEOUT_MS);
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(resolve(draft, call)).openConnection();
            connection.setConnectTimeout(connectTimeout);
            connection.setReadTimeout(readTimeout);
            connection.setInstanceFollowRedirects(false);   // 与 java.net.http 默认一致：不跟随重定向
            draft.headers().forEach(connection::addRequestProperty);
            boolean normalizedGet = "GET".equals(draft.method()) || "HEAD".equals(draft.method());
            if (normalizedGet) {
                connection.setRequestMethod("GET");
            } else {
                connection.setRequestMethod(draft.method());
                connection.setDoOutput(true);
                byte[] wire = draft.wireBody() == null ? new byte[0] : draft.wireBody();
                // 不设 setFixedLengthStreamingMode（保持默认缓冲模式，wire 本就是内存 byte[]）：
                // streaming 模式下 JDK 遇 401/407 直接断连并丢弃错误响应体，
                // getErrorStream() 恒 null → 错误信封读不到且被误报"响应体被截断"。
                // 代价：默认缓冲在 JDK 侧再持有一份请求体（峰值约 2x wire）——
                // HttpURLConnection 无有界缓冲可选，重开流式会复发丢体；体量上限由网关承担（OP_GW_2006）
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(wire);
                }
            }
            int status = connection.getResponseCode();
            if (Thread.currentThread().isInterrupted()) {
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

    private static Map<String, String> collectHeaders(HttpURLConnection connection) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : connection.getHeaderFields().entrySet()) {
            if (entry.getKey() != null) {
                headers.put(entry.getKey().toLowerCase(), entry.getValue().get(0));
            }
        }
        return headers;
    }

    private static byte[] readEntity(HttpURLConnection connection, int status) throws IOException {
        InputStream stream = connection.getErrorStream();
        if (stream == null && !isBodyless(status) && status < 400) {
            stream = connection.getInputStream();
        }
        return verifyLength(connection, status, stream == null ? new byte[0] : readBodyLimited(stream));
    }

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

    private static boolean isBodyless(int status) {
        return status == HttpURLConnection.HTTP_NO_CONTENT || status == HttpURLConnection.HTTP_NOT_MODIFIED;
    }

    private static boolean isSupportedMethod(String method) {
        return SUPPORTED_METHODS.contains(" " + method + " ");
    }

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

    private static int resolveTimeout(int fromCall, int defaultMs) {
        return fromCall > 0 ? fromCall : defaultMs;
    }

    private static String trimBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            return null;
        }
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }
}
