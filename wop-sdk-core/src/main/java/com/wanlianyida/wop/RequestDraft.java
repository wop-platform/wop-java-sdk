package com.wanlianyida.wop;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 出向请求草稿（协议核心输出，零网络 IO）：商户可直接交给任意 HTTP 栈发送，
 * 或使用官方 Transport 适配器。
 * <p>
 * 不可变值对象（record 等价语义：equals/hashCode 按全部字段，数组字段引用比较；
 * headers 构造时防御性拷贝为不可变视图）。
 */
public final class RequestDraft {

    /** HTTP 方法（统一大写）。 */
    private final String method;

    /** 请求路径（以 / 开头；适配器按需拼接 baseUrl）。 */
    private final String path;

    /** 完整协议头（全小写名，含 x-wop-sign），不可变。 */
    private final Map<String, String> headers;

    /** 线上报文字节：L0 = 原始 body；L2 = {"encrypted":"..."} 密文信封；无 body 为 null。 */
    private final byte[] wireBody;

    public RequestDraft(String method, String path, Map<String, String> headers, byte[] wireBody) {
        this.method = method;
        this.path = path;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        this.wireBody = wireBody;
    }

    /** HTTP 方法（统一大写）。 */
    public String method() {
        return method;
    }

    /** 请求路径（以 / 开头）。 */
    public String path() {
        return path;
    }

    /** 完整协议头（全小写名，含 x-wop-sign），不可变。 */
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
