package com.wanlianyida.wop;

import java.util.Map;

/**
 * 出向请求草稿（协议核心输出，零网络 IO）：商户可直接交给任意 HTTP 栈发送，
 * 或使用官方 Transport 适配器。
 *
 * @param method   HTTP 方法（统一大写）
 * @param path     请求路径（以 / 开头；适配器按需拼接 baseUrl）
 * @param headers  完整协议头（全小写名，含 x-wop-sign），不可变
 * @param wireBody 线上报文字节：L0 = 原始 body；L2 = {"encrypted":"..."} 密文信封；无 body 为 null
 */
public record RequestDraft(String method, String path, Map<String, String> headers, byte[] wireBody) {

    public RequestDraft {
        headers = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(headers));
    }
}
