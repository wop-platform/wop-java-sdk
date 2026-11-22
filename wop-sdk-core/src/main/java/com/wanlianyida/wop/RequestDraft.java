package com.wanlianyida.wop;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class RequestDraft {

    private final String method;

    /** 请求路径（以 / 开头；适配器按需拼接 baseUrl）。 */
    private final String path;

    private final Map<String, String> headers;

    private final byte[] wireBody;

    public RequestDraft(String method, String path, Map<String, String> headers, byte[] wireBody) {
        this.method = method;
        this.path = path;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        this.wireBody = wireBody;
    }

    public String method() {
        return method;
    }

    public String path() {
        return path;
    }

    public Map<String, String> headers() {
        return headers;
    }

    /** 线上报文字节；无 body 为 null。 */
    public byte[] wireBody() {
        return wireBody;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RequestDraft)) {
            return false;
        }
        RequestDraft that = (RequestDraft) o;
        return Objects.equals(method, that.method) && Objects.equals(path, that.path)
                && Objects.equals(headers, that.headers) && Objects.equals(wireBody, that.wireBody);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, path, headers, wireBody);
    }

    @Override
    public String toString() {
        return "RequestDraft[method=" + method + ", path=" + path
                + ", headers=" + headers + ", wireBody=" + wireBody + "]";
    }
}
