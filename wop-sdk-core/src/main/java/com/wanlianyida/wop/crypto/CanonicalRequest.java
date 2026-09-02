package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopSdkException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * F2 规范请求 canonicalRequest 构造器（加签与验签共用，SDK 承接 spec §1.3 排除项）。
 * <p>
 * 结构（5 段 '\n' 连接，空段不可省略）：
 * <pre>{@code
 * authString
 * httpRequestMethod（统一大写）
 * canonicalURI
 * canonicalQueryString（POST 为空串，分隔空行保留）
 * canonicalHeaders
 * }</pre>
 * 规范标头：名称 lowercase + trimall + urlencode，值 trimall + urlencode，
 * 按名称 ASCII 升序，行间 '\n' 连接，尾行不加 '\n'。
 * urlencode = Java URLEncoder 语义（空格 '+' 替换回 %20；';'→%3B 与 D2 注记一致）。
 */
public final class CanonicalRequest {

    /** 工具类禁实例化。 */
    private CanonicalRequest() {
    }

    /** RFC 3986 风格 urlencode：空格统一为 %20（URLEncoder 输出 '+' 需替换回来）。 */
    public static String urlencode(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return urlencode(text, "UTF-8").replace("+", "%20");
    }

    /**
     * urlencode（charset 名参数化）。
     * <p>
     * JDK 8 的 {@link URLEncoder#encode(String, String)} 抛受检异常（JDK 10 才有 Charset 重载）；
     * 参数化 charset 名使「不支持的字符集」分支可被测试真实触达（100% 覆盖率门禁不接受死分支），
     * 对外路径恒为 UTF-8。
     */
    static String urlencode(String text, String charsetName) {
        try {
            return URLEncoder.encode(text, charsetName);
        } catch (java.io.UnsupportedEncodingException e) {
            throw new WopSdkException("urlencode 不支持的字符集: " + charsetName, e);
        }
    }

    /** Trimall：去首尾空白，连续空白折叠为单个空格。 */
    public static String trimall(String text) {
        if (text == null) {
            return "";
        }
        return text.trim().replaceAll("\\s+", " ");
    }

    /** 规范标头（名称排序 + 编码，见类注释）。 */
    public static String canonicalHeaders(Map<String, String> headers) {
        TreeMap<String, String> sorted = new TreeMap<>();
        if (headers != null) {
            headers.forEach((name, value) ->
                    sorted.put(trimall(name).toLowerCase(Locale.ROOT), trimall(value)));
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            if (sb.length() != 0) {
                sb.append('\n');
            }
            sb.append(urlencode(entry.getKey())).append(':').append(urlencode(entry.getValue()));
        }
        return sb.toString();
    }

    /** 组装规范请求（5 段）。 */
    public static String build(String authString, String method, String canonicalUri,
                               String queryString, String canonicalHeaders) {
        String safeMethod = method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
        return (authString == null ? "" : authString) + "\n"
                + safeMethod + "\n"
                + (canonicalUri == null ? "" : canonicalUri) + "\n"
                + (queryString == null ? "" : queryString) + "\n"
                + (canonicalHeaders == null ? "" : canonicalHeaders);
    }
}
